package ghistabs.builder

import ghistabs.parser.*
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PolymorphicBaseTest {
    @Test
    fun `polyBase - direct polymorphic base detected`() {
        // Base with vtable marker
        val base = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = true,
            vtableTargetTypeId = null,
        )

        // Derived inherits from Base
        val derived = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases =
            listOf(
                BaseDecl(
                    type = TypeDecl.InlineDef(TypeId(0, 1), base),
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

        val structAstsByName = mapOf<String, TypeDecl.Struct>()
        val result = ClassBuilderHelpers.hasPolymorphicBaseSubobject(derived, structAstsByName)
        assertTrue(result)
    }

    @Test
    fun `nonPolyBase - no virtual methods or markers detected`() {
        // Base with no vtable marker or virtuals
        val base = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        // Derived inherits from non-poly Base
        val derived = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(
                BaseDecl(
                    type = TypeDecl.InlineDef(TypeId(0, 1), base),
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

        val structAstsByName = mapOf<String, TypeDecl.Struct>()
        val result = ClassBuilderHelpers.hasPolymorphicBaseSubobject(derived, structAstsByName)
        assertFalse(result)
    }

    @Test
    fun `transitive - polymorphism inherited through intermediate class`() {
        // Base is polymorphic
        val base = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = true,
            vtableTargetTypeId = null,
        )

        // Middle inherits from Base
        val middle = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(
                BaseDecl(
                    type = TypeDecl.InlineDef(TypeId(0, 1), base),
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

        // Derived inherits from Middle, which transitively has poly base
        val derived = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 16L,
            bases = listOf(
                BaseDecl(
                    type = TypeDecl.InlineDef(TypeId(0, 2), middle),
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

        val structAstsByName = mapOf<String, TypeDecl.Struct>()
        val result = ClassBuilderHelpers.hasPolymorphicBaseSubobject(derived, structAstsByName)
        assertTrue(result)
    }

    @Test
    fun `noBases - empty bases list returns false`() {
        val derived = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        val result = ClassBuilderHelpers.hasPolymorphicBaseSubobject(derived, mapOf())
        assertFalse(result)
    }

    @Test
    fun `virtual method marker - base with virtual method detected as polymorphic`() {
        // Base has a virtual method
        val base = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = listOf(
                MethodDecl(
                    name = "foo",
                    mangled = "_ZN4BaseC1Ev",
                    signature = TypeDecl.FunctionT(ret = TypeDecl.Builtin, params = emptyList()),
                    access = Access.PUBLIC,
                    virt = VirtKind.VIRTUAL,
                    isConst = false,
                    isVolatile = false,
                    vtableOffsetBits = null,
                ),
            ),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        val derived = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(
                BaseDecl(
                    type = TypeDecl.InlineDef(TypeId(0, 1), base),
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

        val structAstsByName = mapOf<String, TypeDecl.Struct>()
        val result = ClassBuilderHelpers.hasPolymorphicBaseSubobject(derived, structAstsByName)
        assertTrue(result)
    }

    @Test
    fun `TypeDecl_Ref base - resolved via typeAstsById map`() {
        // Base is polymorphic (has virtual method)
        val baseTypeId = TypeId(0, 99)
        val base = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = listOf(
                MethodDecl(
                    name = "virtualMethod",
                    mangled = "_ZN4BaseC1Ev",
                    signature = TypeDecl.FunctionT(ret = TypeDecl.Builtin, params = emptyList()),
                    access = Access.PUBLIC,
                    virt = VirtKind.VIRTUAL,
                    isConst = false,
                    isVolatile = false,
                    vtableOffsetBits = null,
                ),
            ),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        // Derived references Base via TypeDecl.Ref (by TypeId)
        val derived = TypeDecl.Struct(
            kind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(
                BaseDecl(
                    type = TypeDecl.Ref(baseTypeId),
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

        // TypeAst wrapping the base struct
        val baseTypeAst = TypeAst(baseTypeId, "Base", base, "test.c")

        val structAstsByName = mapOf<String, TypeDecl.Struct>()
        val typeAstsById = mapOf(baseTypeId to baseTypeAst)

        // Should resolve base via typeAstsById and detect polymorphism
        val result = ClassBuilderHelpers.hasPolymorphicBaseSubobject(derived, structAstsByName, typeAstsById)
        assertTrue(result)
    }
}
