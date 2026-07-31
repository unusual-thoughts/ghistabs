package ghistabs.materialize.itanium

import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.parse.*
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VfptrDecisionTest {
    @Test
    fun `skipInheritedFromBase - poly base present returns skip action`() {
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = true,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.SkipInheritedFromBase)
    }

    @Test
    fun `noParserVptr noComponent - insert at offset 0`() {
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = null,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Insert)
        assertTrue((action as VfptrAction.Insert).offsetBytes == 0)
    }

    @Test
    fun `parserVptrAt4 noComponent - insert at offset 4`() {
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 4,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Insert)
        assertTrue((action as VfptrAction.Insert).offsetBytes == 4)
    }

    @Test
    fun `canonicalVfptrAtOffset - already canonical action`() {
        val snapshot = FirstComponentSnapshot(fieldName = "{vfptr}", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.AlreadyCanonical)
    }

    @Test
    fun `parserEmittedVptrAtOffset - replace action with old name`() {
        val snapshot = FirstComponentSnapshot(fieldName = "_vptr\$Foo", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Replace)
        val replace = action as VfptrAction.Replace
        assertTrue(replace.offsetBytes == 0)
        assertTrue(replace.wasFieldName == "_vptr\$Foo")
    }

    @Test
    fun `regularFieldAtOffset - collision action`() {
        val snapshot = FirstComponentSnapshot(fieldName = "x", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.CollisionAt)
        val collision = action as VfptrAction.CollisionAt
        assertTrue(collision.offsetBytes == 0)
        assertTrue(collision.occupantFieldName == "x")
    }

    @Test
    fun `baseSubobjectAtOffset - skip inherited (no collision)`() {
        // CLexStream → ios_base cascade: the unresolved base occupies offset 0 as
        // a synthesised `_base_unknown_0` field. firstPolymorphicBase couldn't
        // prove polymorphism (base type doesn't resolve), but the layout still
        // hands us a base subobject at the vfptr offset; we must not overwrite it.
        val snapshot = FirstComponentSnapshot(fieldName = "_base_unknown_0", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.SkipInheritedFromBase)
    }

    @Test
    fun `resolvedBaseAtOffset - skip inherited (no collision)`() {
        val snapshot = FirstComponentSnapshot(fieldName = "_base_CLexStream", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.SkipInheritedFromBase)
    }

    @Test
    fun `undefinedSlot - insert action`() {
        val snapshot = FirstComponentSnapshot(fieldName = null, offsetBytes = 0, isUndefined = true)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Insert)
    }
}

class PolymorphicBaseTest {
    private val cu = SourceFile.CUSource("test.cpp")
    private fun gid(n: Int) = GlobalTypeId(cu, n)

    private fun polyStruct(hasVtableMarker: Boolean = false, methods: List<MethodDecl<GlobalTypeId>> = emptyList()) =
        TypeDecl.Struct(
            rawKind = AggrKind.CLASS,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = methods,
            vptrBasetype = if (hasVtableMarker) TypeDecl.Ref(gid(0)) else null,
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

    private fun inlineBase(n: Int, body: TypeDecl.Struct<GlobalTypeId>) = BaseDecl(
        type = TypeDecl.InlineDef(gid(n), body),
        isVirtual = false,
        access = Access.PUBLIC,
        offsetBits = 0L,
    )

    @Test
    fun `polyBase - direct polymorphic base detected`() {
        val base = polyStruct(hasVtableMarker = true)
        val derived = TypeDecl.Struct(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        assertTrue(TypeResolver.Empty.hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `nonPolyBase - no virtual methods or markers detected`() {
        val base = polyStruct(hasVtableMarker = false)
        val derived = TypeDecl.Struct(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        assertFalse(TypeResolver.Empty.hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `transitive - polymorphism inherited through intermediate class`() {
        val base = polyStruct(hasVtableMarker = true)
        val middle = TypeDecl.Struct(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val derived = TypeDecl.Struct(
            rawKind = AggrKind.CLASS,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        assertTrue(TypeResolver.Empty.hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `noBases - empty bases list returns false`() {
        val derived = polyStruct(hasVtableMarker = false)
        assertFalse(TypeResolver.Empty.hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `virtual method in base - detected as polymorphic`() {
        val base = polyStruct(methods = listOf(virtualMethod("foo")))
        val derived = TypeDecl.Struct(
            rawKind = AggrKind.CLASS,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        assertTrue(TypeResolver.Empty.hasPolymorphicBaseSubobject(derived))
    }

    @Test
    fun `TypeDecl_Ref base - resolved via TypeResolver map`() {
        val baseId = gid(99)
        val base = polyStruct(methods = listOf(virtualMethod("virtualMethod")))
        val baseAst = TypeAst(cu, baseId, "Base", base)

        val derived = TypeDecl.Struct(
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
            vptrBasetype = null,
        )
        assertTrue(TypeResolver(Harvest.of(mapOf(baseId to baseAst))).hasPolymorphicBaseSubobject(derived))
    }
}
