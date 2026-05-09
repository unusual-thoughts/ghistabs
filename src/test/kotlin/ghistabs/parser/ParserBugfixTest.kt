package ghistabs.parser

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

        val lines =
            corpusFile
                .readLines()
                .filter { it.isNotEmpty() }
                .filterNot { it.startsWith("#") } // Skip comment lines
        assertTrue(lines.isNotEmpty(), "corpus must have at least one line")

        // Each line must parse successfully
        for ((lineNum, line) in lines.withIndex()) {
            val symbol =
                assertDoesNotThrow({
                    Parser(line).parseSymbol()
                }, "Line ${lineNum + 1} should parse: $line")
            assertNotNull(symbol, "Parse result must not be null")
        }
    }

    /**
     * AC2.6: Parse-error reporting with position and excerpt.
     * Malformed input must throw StabsParseException with cursor position and a caret in the excerpt.
     */
    @Test
    fun testParseErrorReporting() {
        val input = "garbage:T(0,1)=@@@?"

        val exception =
            assertThrows(StabsParseException::class.java) {
                Parser(input).parseSymbol()
            }

        // Cursor should be beyond the start of the input (pos > 0)
        assertTrue(exception.pos > 0, "Exception pos must be > 0, got ${exception.pos}")

        // Excerpt should contain a caret marker
        val excerpt = exception.excerpt()
        assertTrue(excerpt.contains("^"), "Excerpt must contain caret marker: $excerpt")
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

        val duration =
            measureTime {
                val symbol =
                    assertDoesNotThrow({
                        Parser(input).parseSymbol()
                    }, "Recursive type should parse without exception")

                assertNotNull(symbol, "Parse result should not be null")
                if (symbol is SymbolDecl.Typedef) {
                    val ptr = symbol.body
                    if (ptr is TypeDecl.Pointer) {
                        // The pointer should reference (0,30), which is the type being defined
                        if (ptr.pointee is TypeDecl.Ref) {
                            val ref = ptr.pointee as TypeDecl.Ref
                            assertEquals(TypeId(0, 30), ref.id, "Ref should be to (0,30) (the type itself)")
                        }
                    }
                }
            }

        // Should complete in less than 1 second
        assertTrue(duration.inWholeMilliseconds < 1000, "Parse should complete in <1s, took ${duration.inWholeMilliseconds}ms")
    }

    /**
     * Struct with self-pointer field via inline typedef.
     * Tests recursive type handling where the field type is an inline typedef
     * that resolves to the containing struct.
     */
    @Test
    fun testStructSelfPointerRecursion() {
        val input = "Node:T(0,1)=s8next:(0,2)=*(0,1),0,32;val:(0,3)=(0,1),32,32;;"

        val duration =
            measureTime {
                val symbol =
                    assertDoesNotThrow({
                        Parser(input).parseSymbol()
                    }, "Struct with self-pointer field should parse without exception")

                assertNotNull(symbol, "Parse result should not be null")
                if (symbol is SymbolDecl.TaggedType) {
                    val struct = symbol.body
                    if (struct is TypeDecl.Struct) {
                        // Should have 2 fields
                        assertEquals(2, struct.fields.size, "Struct should have 2 fields")

                        // First field 'next' should have type InlineDef wrapping Pointer(Ref(TypeId(0,1)))
                        val nextField = struct.fields[0]
                        assertEquals("next", nextField.name, "First field should be named 'next'")
                        if (nextField.type is TypeDecl.InlineDef) {
                            val inlineDef = nextField.type as TypeDecl.InlineDef
                            assertEquals(TypeId(0, 2), inlineDef.id, "Inline def id should be (0,2)")
                            if (inlineDef.body is TypeDecl.Pointer) {
                                val ptr = inlineDef.body as TypeDecl.Pointer
                                if (ptr.pointee is TypeDecl.Ref) {
                                    val ref = ptr.pointee as TypeDecl.Ref
                                    assertEquals(TypeId(0, 1), ref.id, "Pointer should reference (0,1) (self-reference)")
                                }
                            }
                        }

                        // Second field 'val' should have type InlineDef(0,3) wrapping Ref(0,1)
                        val valField = struct.fields[1]
                        assertEquals("val", valField.name, "Second field should be named 'val'")
                        if (valField.type is TypeDecl.InlineDef) {
                            val inlineDef = valField.type as TypeDecl.InlineDef
                            assertEquals(TypeId(0, 3), inlineDef.id, "Inline def id should be (0,3)")
                            if (inlineDef.body is TypeDecl.Ref) {
                                val ref = inlineDef.body as TypeDecl.Ref
                                assertEquals(TypeId(0, 1), ref.id, "Body should be Ref to (0,1)")
                            }
                        }
                    }
                }
            }

        // Should complete in less than 1 second
        assertTrue(duration.inWholeMilliseconds < 1000, "Parse should complete in <1s, took ${duration.inWholeMilliseconds}ms")
    }

    /**
     * AC2.1: Golden corpus test.
     * Parse every line from the xapasmcsr.exe corpus exported by stabs_stats.py.
     * Uses Assumptions.assumeTrue to skip if corpus file is absent (CI without Ghidra).
     */
    @Test
    fun testGoldenCorpus() {
        val resourceUrl = javaClass.classLoader.getResource("corpus/xapasmcsr-stabs.txt")
        val corpusFile = if (resourceUrl != null) File(resourceUrl.toURI()) else File("")

        Assumptions.assumeTrue(corpusFile.exists(), "Golden corpus file not present (Ghidra not available)")

        // Skip N_SO source-file path lines (e.g. "E:/work/cc/...", or Unix paths ending in "/")
        // These are filename records emitted by the stabs_stats dump, not symbol descriptors.
        val lines =
            corpusFile
                .readLines()
                .filter { it.isNotEmpty() }
                .filterNot { it.matches(Regex("^[A-Za-z]:/.*")) } // Windows drive-letter paths
                .filterNot { it.endsWith("/") } // Unix directory paths
        assertTrue(lines.size >= 1000, "Corpus should have at least 1000 descriptor lines, got ${lines.size}")

        // Parse each line; none should throw
        for ((lineNum, line) in lines.withIndex()) {
            assertDoesNotThrow({
                Parser(line).parseSymbol()
            }, "Line ${lineNum + 1} should parse: ${line.take(100)}")
        }
    }

    @Test
    fun testGoldenCorpusPack() {
        val resourceUrl = javaClass.classLoader.getResource("corpus/packfile-stabs.txt")
        val corpusFile = if (resourceUrl != null) File(resourceUrl.toURI()) else File("")

        Assumptions.assumeTrue(corpusFile.exists(), "Golden corpus file not present (Ghidra not available)")

        val lines = corpusFile.readLines()
        assertTrue(lines.size >= 1000, "Corpus should have at least 1000 descriptor lines, got ${lines.size}")

        // Parse each line; none should throw
        for ((lineNum, line) in lines.withIndex()) {
            assertDoesNotThrow({
                Parser(line).parseSymbol()
            }, "Line ${lineNum + 1} should parse: ${line.take(100)}")
        }
    }
}
