package ghistabs.parse

import ghistabs.parse.TypeDecl.Struct.Field
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.time.measureTime

/**
 * ParserBugfixTest: Tests for issue-#2 bug strings, error reporting, recursive types, and golden corpus.
 *
 * Verifies AC2.1 (golden corpus), AC2.5 (issue-#2 strings), AC2.6 (error reporting), and AC2.7 (recursive types).
 */
@Suppress("USELESS_IS_CHECK", "UNCHECKED_CAST")
class ParserBugfixTest {
    /**
     * AC2.5: Parse issue-#2 bug strings that previously failed.
     * These are explicitly known Cygwin gcc 3.4.4 forms that the parser must handle.
     */
    @Test
    fun testIssue2Strings() {
        val resourceUrl = javaClass.classLoader.getResource("corpus/issue2-strings.txt")
        requireNotNull(resourceUrl) { "corpus/issue2-strings.txt not found in classpath" }

        val corpusFile = File(resourceUrl.toURI())
        assertTrue(corpusFile.exists(), "corpus file must exist")

        val lines = corpusFile
            .readLines()
            .filter { it.isNotEmpty() }
            .filterNot { it.startsWith("#") } // Skip comment lines
        assertTrue(lines.isNotEmpty(), "corpus must have at least one line")

        // Each line must parse successfully
        for ((lineNum, line) in lines.withIndex()) {
            val symbol = assertDoesNotThrow({
                Parser(line).parseSymbol().expectOk()
            }, "Line ${lineNum + 1} should parse: $line")
            assertNotNull(symbol, "Parse result must not be null")
        }
    }

    /**
     * AC2.6: Parse-error reporting with position and excerpt.
     * Malformed input must yield a StabsParseException with cursor position and a caret in the excerpt.
     */
    @Test
    fun testParseErrorReporting() {
        val input = "garbage:T(0,1)=@@@?"

        val exception = Parser(input).parseSymbol().expectError()

        // Cursor should be beyond the start of the input (pos > 0)
        assertTrue(exception.pos > 0, "Exception pos must be > 0, got ${exception.pos}")

        // Excerpt should contain a caret marker
        val excerpt = exception.excerpt()
        assertTrue(excerpt.contains("^"), "Excerpt must contain caret marker: $excerpt")
    }

    /**
     * An unimplemented symbol descriptor must be rejected rather than misread as a stack local
     * with an array/struct type. `a` (array-arg) is a real gdb descriptor g++/x86 never emits;
     * if it ever appears we want a hard parse-error, not a silently-wrong type.
     */
    @Test
    fun testUnknownSymbolDescriptorRejected() {
        val exception = Parser("weird:a(0,1)").parseSymbol().expectError()
        assertTrue(
            exception.message!!.contains("unhandled symbol descriptor 'a'"),
            "message should name the descriptor: ${exception.message}",
        )
    }

    /**
     * AC2.7: Recursive type definitions must not cause infinite recursion.
     * Parse a type that references itself through a pointer, which the parser
     * handles via forward references (Ref nodes) — no infinite recursion should occur.
     */
    @Test
    fun testRecursiveTypeNoInfiniteLoop() {
        // A simple pointer-to-forward-ref that would cause infinite recursion
        // if the parser didn't break cycles via Ref nodes.
        val input = "ptr:t(0,30)=*(0,30)"

        val duration = measureTime {
            val symbol = Parser(input).parseSymbol().expectOk()

            assertNotNull(symbol, "Parse result should not be null")
            if (symbol is SymbolDecl.NamedType) {
                val ptr = symbol.type
                if (ptr is TypeDecl.Pointer) {
                    // The pointer should reference (0,30), which is the type being defined
                    if (ptr.pointee is TypeDecl.Ref) {
                        val ref = ptr.pointee
                        assertEquals(LocalTypeId(0, 30), ref.id, "Ref should be to (0,30) (the type itself)")
                    }
                }
            }
        }

        // Should complete in less than 1 second
        assertTrue(
            duration.inWholeMilliseconds < 1000,
            "Parse should complete in <1s, took ${duration.inWholeMilliseconds}ms",
        )
    }

    /**
     * Struct with self-pointer field via inline typedef.
     * Tests recursive type handling where the field type is an inline typedef
     * that resolves to the containing struct.
     */
    @Test
    fun testStructSelfPointerRecursion() {
        val input = "Node:T(0,1)=s8next:(0,2)=*(0,1),0,32;val:(0,3)=(0,1),32,32;;"

        val duration = measureTime {
            val symbol = Parser(input).parseSymbol().expectOk()

            assertNotNull(symbol, "Parse result should not be null")
            if (symbol is SymbolDecl.NamedType) {
                val struct = symbol.type
                if (struct is TypeDecl.Struct) {
                    // Should have 2 fields
                    assertEquals(2, struct.fields.size, "Struct should have 2 fields")

                    // First field 'next' should have type InlineDef wrapping Pointer(Ref(TypeId(0,1)))
                    val nextField = struct.fields[0]
                    assertEquals("next", nextField.name, "First field should be named 'next'")
                    if (nextField.type is TypeDecl.InlineDef) {
                        val inlineDef = nextField.type
                        assertEquals(LocalTypeId(0, 2), inlineDef.id, "Inline def id should be (0,2)")
                        if (inlineDef.body is TypeDecl.Pointer) {
                            val ptr = inlineDef.body
                            if (ptr.pointee is TypeDecl.Ref) {
                                val ref = ptr.pointee
                                assertEquals(
                                    LocalTypeId(0, 1),
                                    ref.id,
                                    "Pointer should reference (0,1) (self-reference)",
                                )
                            }
                        }
                    }

                    // Second field 'val' should have type InlineDef(0,3) wrapping Ref(0,1)
                    val valField = struct.fields[1]
                    assertEquals("val", valField.name, "Second field should be named 'val'")
                    if (valField.type is TypeDecl.InlineDef) {
                        val inlineDef = valField.type
                        assertEquals(LocalTypeId(0, 3), inlineDef.id, "Inline def id should be (0,3)")
                        if (inlineDef.body is TypeDecl.Ref) {
                            val ref = inlineDef.body
                            assertEquals(LocalTypeId(0, 1), ref.id, "Body should be Ref to (0,1)")
                        }
                    }
                }
            }
        }

        // Should complete in less than 1 second
        assertTrue(
            duration.inWholeMilliseconds < 1000,
            "Parse should complete in <1s, took ${duration.inWholeMilliseconds}ms",
        )
    }

    /**
     * AC2.1: Golden corpus test.
     * Parse every line from the bouniafbouniaf.exe corpus exported by stabs_stats.py.
     * Uses Assumptions.assumeTrue to skip if corpus file is absent (CI without Ghidra).
     */
    @Test
    fun testGoldenCorpus() {
        val resourceUrl = javaClass.classLoader.getResource("corpus/bouniafbouniaf-stabs.txt")
        val corpusFile = if (resourceUrl != null) File(resourceUrl.toURI()) else File("")

        Assumptions.assumeTrue(corpusFile.exists(), "Golden corpus file not present (Ghidra not available)")

        // Skip N_SO source-file path lines (e.g. "E:/work/cc/...", or Unix paths ending in "/")
        // These are filename records emitted by the stabs_stats dump, not symbol descriptors.
        val lines = corpusFile
            .readLines()
            .filter { it.isNotEmpty() }
            .filterNot { it.matches(Regex("^[A-Za-z]:/.*")) } // Windows drive-letter paths
            .filterNot { it.endsWith("/") } // Unix directory paths
        assertTrue(lines.size >= 1000, "Corpus should have at least 1000 descriptor lines, got ${lines.size}")

        // Parse each line; none should throw
        for ((lineNum, line) in lines.withIndex()) {
            assertDoesNotThrow({
                Parser(line).parseSymbol().expectOk()
            }, "Line ${lineNum + 1} should parse: ${line.take(100)}")
        }
    }

    @Test
    fun testGcc345ParsingErrorDoubleColon() {
        val resourceUrl = javaClass.classLoader.getResource("corpus/crypto_gcc345.txt")
        val corpusFile = if (resourceUrl != null) File(resourceUrl.toURI()) else File("")

        Assumptions.assumeTrue(corpusFile.exists(), "crypto_gcc345 corpus file not present")

        val lines = corpusFile.readLines()

        // Parse each line; none should throw
        for ((lineNum, line) in lines.withIndex()) {
            assertDoesNotThrow({
                Parser(line).parseSymbol().expectOk()
            }, "Line ${lineNum + 1} should parse: ${line.take(100)}")
        }
    }

    @Test
    fun testGoldenCorpusPack() {
        val resourceUrl = javaClass.classLoader.getResource("corpus/bouniaf-stabs.txt")
        val corpusFile = if (resourceUrl != null) File(resourceUrl.toURI()) else File("")

        Assumptions.assumeTrue(corpusFile.exists(), "Golden corpus file not present (Ghidra not available)")

        val lines = corpusFile.readLines()
        assertTrue(lines.size >= 1000, "Corpus should have at least 1000 descriptor lines, got ${lines.size}")

        // Parse each line; none should throw
        for ((lineNum, line) in lines.withIndex()) {
            assertDoesNotThrow({
                Parser(line).parseSymbol().expectOk()
            }, "Line ${lineNum + 1} should parse: ${line.take(100)}")
        }
    }

    /**
     * Cross-reference forward declaration of a struct (xs descriptor).
     * A struct forward ref by tag name without body definition.
     * stabs PDF §5.10 "Cross-References"
     */
    @Test
    fun testStructXRef() {
        val input = "my_struct:T(0,50)=xsMyStruct:"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "my_struct",
            id = LocalTypeId(0, 50),
            type = TypeDecl.XRef(kind = AggrKind.STRUCT, tagName = "MyStruct"),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    /**
     * Cross-reference forward declaration of a union (xu descriptor).
     * A union forward ref by tag name without body definition.
     * stabs PDF §5.10 "Cross-References"
     */
    @Test
    fun testUnionXRef() {
        val input = "my_union:T(0,51)=xuMyUnion:"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "my_union",
            id = LocalTypeId(0, 51),
            type = TypeDecl.XRef(kind = AggrKind.UNION, tagName = "MyUnion"),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    /**
     * Cross-reference forward declaration of an enum (xe descriptor).
     * An enum forward ref by tag name without body definition.
     * stabs PDF §5.10 "Cross-References"
     */
    @Test
    fun testEnumXRef() {
        val input = "my_enum:T(0,52)=xeMyEnum:"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "my_enum",
            id = LocalTypeId(0, 52),
            type = TypeDecl.XRef(kind = AggrKind.ENUM, tagName = "MyEnum"),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    /**
     * Deeply nested InlineDef: InlineDef containing InlineDef containing Struct.
     * Tests that the parser correctly handles arbitrary nesting depth of inline
     * type definitions without recursion issues.
     *
     * The structure is:
     * - (0,60) = inline definition of (0,61)
     * - (0,61) = inline definition of a struct with field 'inner'
     * - field 'inner' has type (0,62) = inline definition of (0,63)
     * - (0,63) = a struct with field 'value'
     * - field 'value' has type (0,64) = range
     *
     * stabs PDF §5.2 "Defining a Type"
     */
    @Test
    fun testDeeplyNestedInlineDef() {
        // Structure: nested InlineDefs wrapping struct definitions
        // Outer: (0,60) = (0,61) = struct { inner : (0,62) = ... }
        // Inner: (0,62) = (0,63) = struct { value : (0,64) = range }
        val input = "nested:T(0,60)=(0,61)=s8inner:(0,62)=(0,63)=s4value:(0,64)=r(0,1);0;32;,0,32;;,0,64;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "nested",
            id = LocalTypeId(0, 60),
            type = TypeDecl.InlineDef(
                id = LocalTypeId(0, 61),
                body = TypeDecl.Struct(
                    rawKind = AggrKind.STRUCT,
                    sizeBytes = 8,
                    bases = emptyList(),
                    fields = listOf(
                        Field(
                            name = "inner",
                            type = TypeDecl.InlineDef(
                                id = LocalTypeId(0, 62),
                                body = TypeDecl.InlineDef(
                                    id = LocalTypeId(0, 63),
                                    body = TypeDecl.Struct(
                                        rawKind = AggrKind.STRUCT,
                                        sizeBytes = 4,
                                        bases = emptyList(),
                                        fields = listOf(
                                            Field(
                                                name = "value",
                                                type = TypeDecl.InlineDef(
                                                    id = LocalTypeId(0, 64),
                                                    body = TypeDecl.Range(LocalTypeId(0, 1), 0, 32),
                                                ),
                                                offsetBits = 0,
                                                sizeBits = 32,
                                                isStatic = false,
                                                access = Access.PUBLIC,
                                                mangled = null,
                                            ),
                                        ),
                                        methods = emptyList(),
                                        vptrBasetype = null,
                                    ),
                                ),
                            ),
                            offsetBits = 0,
                            sizeBits = 64,
                            isStatic = false,
                            access = Access.PUBLIC,
                            mangled = null,
                        ),
                    ),
                    methods = emptyList(),
                    vptrBasetype = null,
                ),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    /**
     * stabs.texinfo §Nested Procedures: a function stab may carry a trailing `,<proc>,<enclosing>`
     * scope specifier (gcc, for function-local classes/functions). It's redundant with the symbol
     * name + the Itanium mangling, so it's consumed and dropped — not left as unparsed trailing.
     */
    @Test
    fun testNestedFunctionScopeSpecifierConsumed() {
        val parser = Parser("Push:f(0,1),Push,main")
        assertEquals(
            SymbolDecl.Function("Push", FunctionScope.FILE, type = TypeDecl.Ref(LocalTypeId(0, 1))),
            parser.parseSymbol().expectOk(),
        )
        assertEquals("", parser.remaining, "scope specifier must be fully consumed")
    }
}
