package ghistabs.materialize

import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.parse.*
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PolymorphicBaseTest {
    private val cu = SourceFile.CUSource("test.cpp")
    private fun gid(n: Int) = GlobalTypeId(cu, n)
    private fun helpers(typeAsts: Map<GlobalTypeId, TypeAst> = emptyMap()) =
        ClassBuilderHelpers(TypeResolver(Harvest(typeAsts)))

    private fun polyStruct(hasVtableMarker: Boolean = false, methods: List<MethodDecl<GlobalTypeId>> = emptyList()) =
        TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = methods,
            hasVTablePointerMarker = hasVtableMarker,
            vtableTargetTypeId = null,
        )

    private fun virtualMethod(name: String) = MethodDecl<GlobalTypeId>(
        name = name,
        mangled = null,
        signature = TypeDecl.FunctionT(TypeDecl.Complex(0, 4), emptyList()),
        access = Access.PUBLIC,
        virt = VirtKind.VIRTUAL,
        isConst = false,
        isVolatile = false,
        vtableOffsetBits = 0L,
    )

    private fun inlineBase(n: Int, body: TypeDecl.Struct<GlobalTypeId>) = BaseDecl<GlobalTypeId>(
        type = TypeDecl.InlineDef(gid(n), body),
        isVirtual = false,
        access = Access.PUBLIC,
        offsetBits = 0L,
    )

    @Test
    fun `polyBase - direct polymorphic base detected`() {
        val base = polyStruct(hasVtableMarker = true)
        val derived = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        assertTrue(helpers().hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `nonPolyBase - no virtual methods or markers detected`() {
        val base = polyStruct(hasVtableMarker = false)
        val derived = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        assertFalse(helpers().hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `transitive - polymorphism inherited through intermediate class`() {
        val base = polyStruct(hasVtableMarker = true)
        val middle = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        val derived = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.CLASS,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle)),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        assertTrue(helpers().hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `noBases - empty bases list returns false`() {
        val derived = polyStruct(hasVtableMarker = false)
        assertFalse(helpers().hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `virtual method in base - detected as polymorphic`() {
        val base = polyStruct(methods = listOf(virtualMethod("foo")))
        val derived = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        assertTrue(helpers().hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `TypeDecl_Ref base - resolved via TypeResolver map`() {
        val baseId = gid(99)
        val base = polyStruct(methods = listOf(virtualMethod("virtualMethod")))
        val baseAst = TypeAst(cu, baseId, "Base", base)

        val derived = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(
                BaseDecl(
                    type = TypeDecl.Ref(baseId),
                    isVirtual = false,
                    access = Access.PUBLIC,
                    offsetBits = 0L,
                ),
            ),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        assertTrue(helpers(mapOf(baseId to baseAst)).hasPolymorphicBaseSubobject(derived))
    }
}
