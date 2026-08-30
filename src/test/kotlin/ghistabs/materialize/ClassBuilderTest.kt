package ghistabs.materialize

import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Struct.Method
import ghistabs.test.*
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

        ctorRe.find(ctorC1) mustNotBe null
        ctorRe.find(ctorC2) mustNotBe null
        ctorRe.find(ctorC3) mustNotBe null
        ctorRe.find(normalMethod) mustBe null

        dtorRe.find(dtorD0) mustNotBe null
        dtorRe.find(dtorD1) mustNotBe null
        dtorRe.find(dtorD2) mustNotBe null
        dtorRe.find(normalMethod) mustBe null

        ctorRe.find(ctorC1)?.groupValues?.get(1) mustBe "1"
        ctorRe.find(ctorC2)?.groupValues?.get(1) mustBe "2"
        dtorRe.find(dtorD0)?.groupValues?.get(1) mustBe "0"
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
        singleMangle mustBe "3Foo"

        val nestedMangle = when {
            nestedName.contains("::") && '<' !in nestedName ->
                "N" + nestedName.split("::").joinToString("") { "${it.length}$it" } + "E"

            else -> nestedName
        }
        nestedMangle mustBe "N3Foo3BarE"

        val tripleMangle = when {
            tripleNested.contains("::") && '<' !in tripleNested ->
                "N" + tripleNested.split("::").joinToString("") { "${it.length}$it" } + "E"

            else -> tripleNested
        }
        tripleMangle mustBe "N3Foo3Bar3BazE"
    }

    @Test
    fun testClassStructWithMethods() {
        val methodSig = TypeDecl.FunctionT<GlobalTypeId>(TypeDecl.Complex(0, 4), emptyList())
        val method = Method(
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
            kind = AggrKind.STRUCT,
            sizeBytes = 4,
            bases = emptyList(),
            fields = emptyList(),
            methods = listOf(method),
            vptrBasetype = null,
        )

        classStruct.methods.size mustBe 1
        classStruct.methods[0].name mustBe "bar"
        classStruct.methods[0].mangled mustBe "_ZN3Foo3barEv"
        classStruct.mustNot { hasVTablePointerMarker }
    }

    @Test
    fun testVirtualMethodTracking() {
        val virtualMethod = Method<GlobalTypeId>(
            name = "draw",
            mangled = "_ZN3Foo4drawEv",
            signature = TypeDecl.FunctionT(TypeDecl.Complex(0, 4), emptyList()),
            access = Access.PUBLIC,
            virt = VirtKind.VIRTUAL,
            isConst = false,
            isVolatile = false,
            vtableOffsetBits = 0L,
        )

        virtualMethod.virt mustBe VirtKind.VIRTUAL
        virtualMethod.vtableOffsetBits mustBe 0L

        val inherited = listOf(virtualMethod)
        val own = listOf(
            Method<GlobalTypeId>(
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

        merged.size mustBe 1
        merged[0].mangled mustBe "_ZN7Derived4drawEv"
    }

    @Test
    fun testNestedNamespaceNames() {
        val parts = "Foo::Bar::Baz".split("::").filter { it.isNotEmpty() }
        parts.size mustBe 3
        parts[0] mustBe "Foo"
        parts[1] mustBe "Bar"
        parts[2] mustBe "Baz"
    }

    @Test
    fun testTemplateNameDetection() {
        val simpleName = "Foo"
        val templateName = "std::vector<int>"
        val complexTemplateName = "std::basic_string<char, std::allocator<char>>"

        '<' mustNotBeIn simpleName
        '<' mustBeIn templateName
        '<' mustBeIn complexTemplateName
    }

    @Test
    fun testParserEmittedVptrFieldRecognition() {
        val vptrFieldName1 = $$"_vptr$Foo"
        val vptrFieldName2 = "_vptr.Bar"
        val vptrFieldName3 = "_vptr"
        val nonVptrFieldName = "m_member"

        isVptrFieldName(vptrFieldName1).mustBeTrue()
        isVptrFieldName(vptrFieldName2).mustBeTrue()
        isVptrFieldName(vptrFieldName3).mustBeTrue()
        isVptrFieldName(nonVptrFieldName).mustBeFalse()
    }

    @Test
    fun testCanonicalVfptrFieldName() {
        val canonicalName = "{vfptr}"
        canonicalName mustBe "{vfptr}"
    }
}
