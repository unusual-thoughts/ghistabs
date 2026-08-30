package ghistabs.materialize.itanium

import ghistabs.harvest.Type
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Struct.Base
import ghistabs.parse.TypeDecl.Struct.Method
import ghistabs.test.*
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
        action.mustBeA<VfptrAction.SkipInheritedFromBase>()
    }

    @Test
    fun `noParserVptr noComponent - insert at offset 0`() {
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = null,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.Insert>()
        (action as VfptrAction.Insert).offsetBytes mustBe 0
    }

    @Test
    fun `parserVptrAt4 noComponent - insert at offset 4`() {
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 4,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.Insert>()
        (action as VfptrAction.Insert).offsetBytes mustBe 4
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
        action.mustBeA<VfptrAction.AlreadyCanonical>()
    }

    @Test
    fun `parserEmittedVptrAtOffset - replace action with old name`() {
        val snapshot = FirstComponentSnapshot(fieldName = $$"_vptr$Foo", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.Replace>()
        val replace = action as VfptrAction.Replace
        replace.offsetBytes mustBe 0
        replace.wasFieldName mustBe $$"_vptr$Foo"
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
        action.mustBeA<VfptrAction.CollisionAt>()
        val collision = action as VfptrAction.CollisionAt
        collision.offsetBytes mustBe 0
        collision.occupantFieldName mustBe "x"
    }

    @Test
    fun `baseSubobjectAtOffset - skip inherited (no collision)`() {
        // bouniaf → ios_base cascade: the unresolved base occupies offset 0 as
        // a synthesized `_base_unknown_0` field. firstPolymorphicBase couldn't
        // prove polymorphism (base type doesn't resolve), but the layout still
        // hands us a base subobject at the vfptr offset; we must not overwrite it.
        val snapshot = FirstComponentSnapshot(fieldName = "_base_unknown_0", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.SkipInheritedFromBase>()
    }

    @Test
    fun `resolvedBaseAtOffset - skip inherited (no collision)`() {
        val snapshot = FirstComponentSnapshot(fieldName = "_base_bouniaf", offsetBytes = 0, isUndefined = false)
        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.SkipInheritedFromBase>()
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
        action.mustBeA<VfptrAction.Insert>()
    }
}

class PolymorphicBaseTest {
    private val cu = SourceFile.CUSource("test.cpp")
    private fun gid(n: Int) = GlobalTypeId(cu, n)

    private fun polyStruct(hasVtableMarker: Boolean = false, methods: List<Method<GlobalTypeId>> = emptyList()) =
        TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = methods,
            vptrBasetype = if (hasVtableMarker) TypeDecl.Ref(gid(0)) else null,
        )

    private fun virtualMethod(name: String) = Method<GlobalTypeId>(
        name = name,
        mangled = null,
        signature = TypeDecl.FunctionT(TypeDecl.Complex(0, 4), emptyList()),
        access = Access.PUBLIC,
        virt = VirtKind.VIRTUAL,
        isConst = false,
        isVolatile = false,
        vtableOffsetBits = 0L,
    )

    private fun inlineBase(n: Int, body: TypeDecl.Struct<GlobalTypeId>) = Base(
        type = TypeDecl.InlineDef(gid(n), body),
        isVirtual = false,
        access = Access.PUBLIC,
        offsetBits = 0L,
    )

    @Test
    fun `polyBase - direct polymorphic base detected`() {
        val base = polyStruct(hasVtableMarker = true)
        val derived = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        indexOf().must { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `nonPolyBase - no virtual methods or markers detected`() {
        val base = polyStruct(hasVtableMarker = false)
        val derived = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        indexOf().mustNot { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `transitive - polymorphism inherited through intermediate class`() {
        val base = polyStruct(hasVtableMarker = true)
        val middle = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val derived = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        indexOf().must { hasPolymorphicBaseSubobject(derived) }
    }

    /**
     * A vtable carries one vbase offset per *distinct* virtual base however deep it was inherited, so
     * the walk cannot stop at directly-declared bases. `std::iostream` is the real case: it declares
     * `istream` and `ostream`, neither virtual, and `__ZTVSd` still has a vbase offset for the
     * `basic_ios` both of them inherit virtually. Counting only direct bases returns zero here, which
     * leaves the word labelled with the "no base list" fallback — or, when the class does have some
     * direct virtual base, mislabels a real vbase offset as a vcall offset.
     *
     * Gated here rather than on a fixture: the integration corpus cannot distinguish the two, because
     * the stabs for its whole iostream family record `basic_istream`'s `basic_ios` edge as
     * non-virtual, so the honest answer there is the fallback either way.
     */
    @Test
    fun `virtualBases - virtual base reached through a non-virtual edge still counts`() {
        val vbase = polyStruct(hasVtableMarker = true)
        val middle = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, vbase).copy(isVirtual = true)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val derived = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        indexOf().virtualBases(derived).map { it.type }.mustBe(listOf(TypeDecl.InlineDef(gid(1), vbase)))
    }

    /** A virtual edge to a class already reached non-virtually still contributes its own vbase
     *  offset, so the walk deduplicates *recursion*, never edge collection. */
    @Test
    fun `virtualBases - virtual edge to an already-visited class is still collected`() {
        val shared = polyStruct(hasVtableMarker = true)
        val middle = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, shared)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val derived = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle), inlineBase(1, shared).copy(isVirtual = true)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        indexOf().virtualBases(derived).size.mustBe(1)
    }

    @Test
    fun `noBases - empty bases list returns false`() {
        val derived = polyStruct(hasVtableMarker = false)
        indexOf().mustNot { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `virtual method in base - detected as polymorphic`() {
        val base = polyStruct(methods = listOf(virtualMethod("foo")))
        val derived = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        indexOf().must { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `TypeDecl_Ref base - resolved via TypeResolver map`() {
        val baseId = gid(99)
        val base = polyStruct(methods = listOf(virtualMethod("virtualMethod")))
        val baseAst = Type(cu, baseId, "Base", base)

        val derived = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(
                Base(type = TypeDecl.Ref(baseId), isVirtual = false, access = Access.PUBLIC, offsetBits = 0L),
            ),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        indexOf(baseAst).must { hasPolymorphicBaseSubobject(derived) }
    }
}
