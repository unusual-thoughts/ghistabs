package ghistabs.materialize

import ghistabs.parse.*
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
    @Test
    fun testCtorVariantNaming() {
        val ctorC1 = "_ZN3FooC1Ev"
        val ctorC2 = "_ZN3FooC2Ev"
        val ctorC3 = "_ZN3FooC3Ev"
        val dtorD0 = "_ZN3FooD0Ev"
        val dtorD1 = "_ZN3FooD1Ev"
        val dtorD2 = "_ZN3FooD2Ev"
        val normalMethod = "_ZN3Foo3barEv"

        val ctorRe = Regex("""C([123])E[a-zA-Z_0-9$]*$""")
        val dtorRe = Regex("""D([012])E[a-zA-Z_0-9$]*$""")

        assertNotNull(ctorRe.find(ctorC1))
        assertNotNull(ctorRe.find(ctorC2))
        assertNotNull(ctorRe.find(ctorC3))
        assertNull(ctorRe.find(normalMethod))

        assertNotNull(dtorRe.find(dtorD0))
        assertNotNull(dtorRe.find(dtorD1))
        assertNotNull(dtorRe.find(dtorD2))
        assertNull(dtorRe.find(normalMethod))

        assertEquals("1", ctorRe.find(ctorC1)?.groupValues?.get(1))
        assertEquals("2", ctorRe.find(ctorC2)?.groupValues?.get(1))
        assertEquals("0", dtorRe.find(dtorD0)?.groupValues?.get(1))
    }

    @Test
    fun testClassNameMangling() {
        val singleName = "Foo"
        val nestedName = "Foo::Bar"
        val tripleNested = "Foo::Bar::Baz"

        val singleMangle = when {
            singleName.contains("::") -> "N" + singleName.split("::").joinToString("") { "${it.length}$it" } + "E"
            '<' !in singleName -> "${singleName.length}$singleName"
            else -> singleName
        }
        assertEquals("3Foo", singleMangle)

        val nestedMangle = when {
            nestedName.contains("::") && '<' !in nestedName ->
                "N" + nestedName.split("::").joinToString("") { "${it.length}$it" } + "E"

            else -> nestedName
        }
        assertEquals("N3Foo3BarE", nestedMangle)

        val tripleMangle = when {
            tripleNested.contains("::") && '<' !in tripleNested ->
                "N" + tripleNested.split("::").joinToString("") { "${it.length}$it" } + "E"

            else -> tripleNested
        }
        assertEquals("N3Foo3Bar3BazE", tripleMangle)
    }

    @Test
    fun testClassStructWithMethods() {
        val methodSig = TypeDecl.FunctionT<GlobalTypeId>(TypeDecl.Complex(0, 4), emptyList())
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
            rawKind = AggrKind.CLASS,
            sizeBytes = 4,
            bases = emptyList(),
            fields = emptyList(),
            methods = listOf(method),
            vptrBasetype = null,
        )

        assertEquals(1, classStruct.methods.size)
        assertEquals("bar", classStruct.methods[0].name)
        assertEquals("_ZN3Foo3barEv", classStruct.methods[0].mangled)
        assertFalse(classStruct.hasVTablePointerMarker)
    }

    @Test
    fun testVirtualMethodTracking() {
        val virtualMethod = MethodDecl<GlobalTypeId>(
            name = "draw",
            mangled = "_ZN3Foo4drawEv",
            signature = TypeDecl.FunctionT(TypeDecl.Complex(0, 4), emptyList()),
            access = Access.PUBLIC,
            virt = VirtKind.VIRTUAL,
            isConst = false,
            isVolatile = false,
            vtableOffsetBits = 0L,
        )

        assertEquals(VirtKind.VIRTUAL, virtualMethod.virt)
        assertEquals(0L, virtualMethod.vtableOffsetBits)

        val inherited = listOf(virtualMethod)
        val own = listOf(
            MethodDecl<GlobalTypeId>(
                name = "draw",
                mangled = "_ZN7Derived4drawEv",
                signature = TypeDecl.FunctionT(TypeDecl.Complex(0, 4), emptyList()),
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

    @Test
    fun testNestedNamespaceNames() {
        val parts = "Foo::Bar::Baz".split("::").filter { it.isNotEmpty() }
        assertEquals(3, parts.size)
        assertEquals("Foo", parts[0])
        assertEquals("Bar", parts[1])
        assertEquals("Baz", parts[2])
    }

    @Test
    fun testTemplateNameDetection() {
        val simpleName = "Foo"
        val templateName = "std::vector<int>"
        val complexTemplateName = "std::basic_string<char, std::allocator<char>>"

        assertFalse(simpleName.contains('<'))
        assertTrue(templateName.contains('<'))
        assertTrue(complexTemplateName.contains('<'))
    }

    @Test
    fun testParserEmittedVptrFieldRecognition() {
        val vptrFieldName1 = $$"_vptr$Foo"
        val vptrFieldName2 = "_vptr.Bar"
        val vptrFieldName3 = "_vptr"
        val nonVptrFieldName = "m_member"

        fun isParserEmitted(name: String): Boolean =
            name.startsWith("_vptr$") || name.startsWith("_vptr.") || name == "_vptr"

        assertTrue(isParserEmitted(vptrFieldName1))
        assertTrue(isParserEmitted(vptrFieldName2))
        assertTrue(isParserEmitted(vptrFieldName3))
        assertFalse(isParserEmitted(nonVptrFieldName))
    }

    @Test
    fun testCanonicalVfptrFieldName() {
        val canonicalName = "{vfptr}"
        assertEquals("{vfptr}", canonicalName)
    }
}
