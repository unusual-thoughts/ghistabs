package ghistabs.materialize

import ghistabs.harvest.Type
import ghistabs.harvest.binding
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Aggregate.Base
import ghistabs.parse.TypeDecl.Aggregate.Method
import ghistabs.test.*
import org.junit.jupiter.api.Test

class PolymorphicBaseTest {
    private val cu = SourceFile.CUSource("test.cpp")
    private fun gid(n: Int) = GlobalTypeId(cu, n)

    private fun polyStruct(hasVtableMarker: Boolean = false, methods: List<Method<GlobalTypeId>> = emptyList()) =
        TypeDecl.Aggregate(
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
        signature = TypeDecl.FreeFunction(TypeDecl.Complex(0, 4), emptyList()),
        access = Access.PUBLIC,
        virt = VirtKind.VIRTUAL,
        isConst = false,
        isVolatile = false,
        vtableOffsetBits = 0L,
    )

    private fun inlineBase(n: Int, body: TypeDecl.Aggregate<GlobalTypeId>) = Base(
        type = TypeDecl.InlineDef(gid(n), body),
        isVirtual = false,
        access = Access.PUBLIC,
        offsetBits = 0L,
    )

    @Test
    fun `polyBase - direct polymorphic base detected`() {
        val base = polyStruct(hasVtableMarker = true)
        val derived = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        typesOf().must { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `nonPolyBase - no virtual methods or markers detected`() {
        val base = polyStruct(hasVtableMarker = false)
        val derived = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        typesOf().mustNot { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `transitive - polymorphism inherited through intermediate class`() {
        val base = polyStruct(hasVtableMarker = true)
        val middle = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val derived = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        typesOf().must { hasPolymorphicBaseSubobject(derived) }
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
        val middle = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, vbase).copy(isVirtual = true)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val derived = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        typesOf().virtualBases(derived).map { it.type }.mustBe(listOf(TypeDecl.InlineDef(gid(1), vbase)))
    }

    /** A virtual edge to a class already reached non-virtually still contributes its own vbase
     *  offset, so the walk deduplicates *recursion*, never edge collection. */
    @Test
    fun `virtualBases - virtual edge to an already-visited class is still collected`() {
        val shared = polyStruct(hasVtableMarker = true)
        val middle = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, shared)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val derived = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = listOf(inlineBase(2, middle), inlineBase(1, shared).copy(isVirtual = true)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        typesOf().virtualBases(derived).size.mustBe(1)
    }

    @Test
    fun `noBases - empty bases list returns false`() {
        val derived = polyStruct(hasVtableMarker = false)
        typesOf().mustNot { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `virtual method in base - detected as polymorphic`() {
        val base = polyStruct(methods = listOf(virtualMethod("foo")))
        val derived = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(inlineBase(1, base)),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        typesOf().must { hasPolymorphicBaseSubobject(derived) }
    }

    @Test
    fun `TypeDecl_Ref base - resolved via TypeResolver map`() {
        val baseId = gid(99)
        val base = polyStruct(methods = listOf(virtualMethod("virtualMethod")))
        val baseAst = Type(cu, baseId, binding("Base", base), base)

        val derived = TypeDecl.Aggregate(
            kind = AggrKind.STRUCT,
            sizeBytes = 12L,
            bases = listOf(
                Base(type = TypeDecl.Ref(baseId), isVirtual = false, access = Access.PUBLIC, offsetBits = 0L),
            ),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )
        typesOf(baseAst).must { hasPolymorphicBaseSubobject(derived) }
    }
}
