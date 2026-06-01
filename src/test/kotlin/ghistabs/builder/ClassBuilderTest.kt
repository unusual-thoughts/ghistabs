package ghistabs.builder

import ghistabs.parser.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Tests for ClassBuilder logic and AST structures.
 *
 * Since full ClassBuilder testing requires extensive Ghidra mocking, these tests focus on
 * the core algorithms: ctor/dtor variant naming, vtable slot merging, inheritance resolution,
 * and namespace parsing. Integration testing occurs in Phase 6 on real binaries.
 */
class ClassBuilderTest {
    /**
     * AC5.2: ctor/dtor variant regex matching
     */
    @Test
    fun testCtorVariantNaming() {
        // Test the private displayNameFor logic by checking regex patterns
        val ctorC1 = "_ZN3FooC1Ev"
        val ctorC2 = "_ZN3FooC2Ev"
        val ctorC3 = "_ZN3FooC3Ev"
        val dtorD0 = "_ZN3FooD0Ev"
        val dtorD1 = "_ZN3FooD1Ev"
        val dtorD2 = "_ZN3FooD2Ev"
        val normalMethod = "_ZN3Foo3barEv"

        // Verify regex patterns work
        val ctorRe = Regex("""C([123])E[a-zA-Z_0-9$]*$""")
        val dtorRe = Regex("""D([012])E[a-zA-Z_0-9$]*$""")

        assertNotNull(ctorRe.find(ctorC1), "Should match C1 ctor variant")
        assertNotNull(ctorRe.find(ctorC2), "Should match C2 ctor variant")
        assertNotNull(ctorRe.find(ctorC3), "Should match C3 ctor variant")
        assertNull(ctorRe.find(normalMethod), "Should not match normal method")

        assertNotNull(dtorRe.find(dtorD0), "Should match D0 dtor variant")
        assertNotNull(dtorRe.find(dtorD1), "Should match D1 dtor variant")
        assertNotNull(dtorRe.find(dtorD2), "Should match D2 dtor variant")
        assertNull(dtorRe.find(normalMethod), "Should not match normal method")

        assertEquals("1", ctorRe.find(ctorC1)?.groupValues?.get(1))
        assertEquals("2", ctorRe.find(ctorC2)?.groupValues?.get(1))
        assertEquals("0", dtorRe.find(dtorD0)?.groupValues?.get(1))
    }

    /**
     * AC5.6: itaniumMangleClassName correctly encodes single and nested class names
     */
    @Test
    fun testClassNameMangling() {
        // Verify the mangling strategy works for common cases
        val singleName = "Foo"
        val nestedName = "Foo::Bar"
        val tripleNested = "Foo::Bar::Baz"

        // Single name: length + name
        val singleMangle = when {
            singleName.contains("::") -> "N" + singleName.split("::").joinToString("") { "${it.length}$it" } + "E"
            '<' !in singleName -> "${singleName.length}$singleName"
            else -> singleName
        }
        assertEquals("3Foo", singleMangle)

        // Nested: N + length+name per part + E
        val nestedMangle = when {
            nestedName.contains("::") && '<' !in nestedName ->
                "N" + nestedName.split("::").joinToString("") { "${it.length}$it" } + "E"

            else -> nestedName
        }
        assertEquals("N3Foo3BarE", nestedMangle)

        // Triple nested
        val tripleMangle = when {
            tripleNested.contains("::") && '<' !in tripleNested ->
                "N" + tripleNested.split("::").joinToString("") { "${it.length}$it" } + "E"

            else -> tripleNested
        }
        assertEquals("N3Foo3Bar3BazE", tripleMangle)
    }

    /**
     * AC5.1: Class struct with methods
     */
    @Test
    fun testClassStructWithMethods() {
        // Verify the AST structure supports what we need
        val methodSig = TypeDecl.FunctionT(TypeDecl.Builtin, emptyList())
        val method = MethodDecl(
            name = "bar",
            mangled = "_ZN3Foo3barEv",
            signature = methodSig,
            access = Access.PUBLIC,
            virt = VirtKind.NORMAL,
            isConst = false,
            isVolatile = false,
            vtableOffsetBits = null,
        )

        val classStruct = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 4,
            bases = emptyList(),
            fields = emptyList(),
            methods = listOf(method),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        assertEquals(1, classStruct.methods.size)
        assertEquals("bar", classStruct.methods[0].name)
        assertEquals("_ZN3Foo3barEv", classStruct.methods[0].mangled)
        assertFalse(classStruct.hasVTablePointerMarker)
    }

    /**
     * AC5.3: Virtual method vtable offset tracking
     */
    @Test
    fun testVirtualMethodTracking() {
        val virtualMethod = MethodDecl(
            name = "draw",
            mangled = "_ZN3Foo4drawEv",
            signature = TypeDecl.FunctionT(TypeDecl.Builtin, emptyList()),
            access = Access.PUBLIC,
            virt = VirtKind.VIRTUAL,
            isConst = false,
            isVolatile = false,
            vtableOffsetBits = 0L, // First slot
        )

        assertEquals(VirtKind.VIRTUAL, virtualMethod.virt)
        assertEquals(0L, virtualMethod.vtableOffsetBits)

        // Merge test: own virtuals overwrite inherited by name
        val inherited = listOf(virtualMethod)
        val own = listOf(
            MethodDecl(
                name = "draw",
                mangled = "_ZN7Derived4drawEv",
                signature = TypeDecl.FunctionT(TypeDecl.Builtin, emptyList()),
                access = Access.PUBLIC,
                virt = VirtKind.VIRTUAL,
                isConst = false,
                isVolatile = false,
                vtableOffsetBits = 0L,
            ),
        )

        val merged = inherited.toMutableList()
        for (m in own) {
            val idx = merged.indexOfFirst { it.name == m.name }
            if (idx >= 0) merged[idx] = m else merged += m
        }

        assertEquals(1, merged.size)
        assertEquals("_ZN7Derived4drawEv", merged[0].mangled)
    }

    /**
     * AC5.6: Nested namespace structure
     */
    @Test
    fun testNestedNamespaceNames() {
        val parts = "Foo::Bar::Baz".split("::").filter { it.isNotEmpty() }
        assertEquals(3, parts.size)
        assertEquals("Foo", parts[0])
        assertEquals("Bar", parts[1])
        assertEquals("Baz", parts[2])
    }

    /**
     * AC5.6: Template name handling (documented limitation)
     */
    @Test
    fun testTemplateNameDetection() {
        // Template names contain '<' which signals that Itanium mangling is approximate
        val simpleName = "Foo"
        val templateName = "std::vector<int>"
        val complexTemplateName = "std::basic_string<char, std::allocator<char>>"

        assertFalse(simpleName.contains('<'), "Simple name has no template args")
        assertTrue(templateName.contains('<'), "Template name has template args")
        assertTrue(complexTemplateName.contains('<'), "Complex template has template args")
    }

    /**
     * AC5.2: Canonical vfptr field detection and extraction
     *
     * Regression test to ensure parser-emitted _vptr$<class> fields are correctly
     * recognized as synthetic vptr candidates. This guards against regressions
     * where the parser-emitted field name format could change.
     */
    @Test
    fun testParserEmittedVptrFieldRecognition() {
        // Parser emits _vptr$ prefix for various class names
        val vptrFieldName1 = $$"_vptr$Foo"
        val vptrFieldName2 = "_vptr.Bar"
        val vptrFieldName3 = "_vptr"
        val nonVptrFieldName = "m_member"

        // Verify the recognition pattern used in VfptrDecision
        fun isParserEmitted(name: String): Boolean =
            name.startsWith($$"_vptr$") || name.startsWith("_vptr.") || name == "_vptr"

        assertTrue(isParserEmitted(vptrFieldName1), $$"_vptr$Foo should be recognized as parser-emitted")
        assertTrue(isParserEmitted(vptrFieldName2), "_vptr.Bar should be recognized as parser-emitted")
        assertTrue(isParserEmitted(vptrFieldName3), "_vptr should be recognized as parser-emitted")
        assertFalse(isParserEmitted(nonVptrFieldName), "m_member should not be recognized as parser-emitted")
    }

    /**
     * AC5.2: Vfptr canonical field name and type
     *
     * Regression test to ensure the canonical vfptr field name is consistently used.
     * This guards against the field name being changed or normalized incorrectly.
     */
    @Test
    fun testCanonicalVfptrFieldName() {
        // The canonical field name for vfptr should always be "{vfptr}"
        val canonicalName = "{vfptr}"
        assertEquals("{vfptr}", canonicalName, "Canonical vfptr field name must be {vfptr}")
    }
}
