package ghistabs.harvest

import ghistabs.parse.*
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class AnonymousTypedefTargetNamesTest {
    private val cu = SourceFile.CUSource("file.c")
    private fun id(n: Int) = GlobalTypeId(cu, n)
    private fun struct(size: Long = 4L) = TypeDecl.Struct<GlobalTypeId>(
        rawKind = AggrKind.STRUCT,
        sizeBytes = size,
        bases = emptyList(),
        fields = emptyList(),
        methods = emptyList(),
        vptrBasetype = null,
    )
    private fun ast(n: Int, name: String?, body: GlobalTypeDecl) = Type(cu = cu, id = id(n), name = name, body = body)
    private fun map(vararg asts: Type) = TypeStore(asts.associateBy { it.id }.toMutableMap())

    @Test fun namesAnonymousInlineStruct() {
        val typedef = ast(3, "sometype", TypeDecl.InlineDef(id(4), struct(36)))
        val anon = ast(4, null, struct(36))
        map(typedef, anon).anonymousTypedefTargetNames() mustBe mapOf(id(4) to "sometype")
    }

    @Test fun leavesTaggedStructAlone() {
        val typedef = ast(3, "Name", TypeDecl.InlineDef(id(4), struct()))
        val tagged = ast(4, "Tag", struct())
        map(typedef, tagged).anonymousTypedefTargetNames() mustBe emptyMap<GlobalTypeId, String>()
    }

    @Test fun ignoresNonAggregateInlineDef() {
        val arr = TypeDecl.Array<GlobalTypeId>(TypeDecl.Builtin(0), 5L, null)
        val typedef = ast(3, "Name", TypeDecl.InlineDef(id(4), arr))
        map(typedef, ast(4, null, arr)).anonymousTypedefTargetNames() mustBe emptyMap<GlobalTypeId, String>()
    }

    @Test fun ambiguousNamesAreSkipped() {
        val td1 = ast(3, "Alpha", TypeDecl.InlineDef(id(5), struct()))
        val td2 = ast(4, "Beta", TypeDecl.InlineDef(id(5), struct()))
        map(td1, td2, ast(5, null, struct())).anonymousTypedefTargetNames() mustBe emptyMap<GlobalTypeId, String>()
    }

    @Test fun refToAnonAggregateNames() {
        // gcc's `typedef enum {…} Name;` — separate anon enum + a Ref typedef.
        val typedef = ast(3, "EnumDSPRev", TypeDecl.Ref(id(4)))
        val anon = ast(4, null, TypeDecl.Enum(listOf("A" to 0L)))
        map(typedef, anon).anonymousTypedefTargetNames() mustBe mapOf(id(4) to "EnumDSPRev")
    }

    @Test fun refToNamedTypeDoesNotRename() {
        // `typedef Existing Alias;` — target already named; a plain alias, leave it.
        val typedef = ast(3, "Alias", TypeDecl.Ref(id(4)))
        map(typedef, ast(4, "Existing", struct())).anonymousTypedefTargetNames() mustBe emptyMap<GlobalTypeId, String>()
    }
}
