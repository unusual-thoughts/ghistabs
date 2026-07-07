package ghistabs.harvest

import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.TypeDecl
import org.junit.jupiter.api.Assertions.assertEquals
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
        hasVTablePointerMarker = false,
        vtableTargetTypeId = null,
    )
    private fun ast(n: Int, name: String?, body: TypeDecl<GlobalTypeId>) =
        TypeAst(cu = cu, id = id(n), name = name, body = body)
    private fun map(vararg asts: TypeAst) = asts.associateBy { it.id }

    @Test fun namesAnonymousInlineStruct() {
        val typedef = ast(3, "sometype", TypeDecl.InlineDef(id(4), struct(36)))
        val anon = ast(4, null, struct(36))
        assertEquals(mapOf(id(4) to "bouniaf"), anonymousTypedefTargetNames(map(typedef, anon)))
    }

    @Test fun leavesTaggedStructAlone() {
        val typedef = ast(3, "Name", TypeDecl.InlineDef(id(4), struct()))
        val tagged = ast(4, "Tag", struct())
        assertEquals(emptyMap<GlobalTypeId, String>(), anonymousTypedefTargetNames(map(typedef, tagged)))
    }

    @Test fun ignoresNonAggregateInlineDef() {
        val arr = TypeDecl.Array<GlobalTypeId>(TypeDecl.Builtin(0), 5L, null)
        val typedef = ast(3, "Name", TypeDecl.InlineDef(id(4), arr))
        assertEquals(emptyMap<GlobalTypeId, String>(), anonymousTypedefTargetNames(map(typedef, ast(4, null, arr))))
    }

    @Test fun ambiguousNamesAreSkipped() {
        val td1 = ast(3, "Alpha", TypeDecl.InlineDef(id(5), struct()))
        val td2 = ast(4, "Beta", TypeDecl.InlineDef(id(5), struct()))
        assertEquals(
            emptyMap<GlobalTypeId, String>(),
            anonymousTypedefTargetNames(map(td1, td2, ast(5, null, struct()))),
        )
    }

    @Test fun refToAnonAggregateNames() {
        // gcc's `typedef enum {…} Name;` — separate anon enum + a Ref typedef.
        val typedef = ast(3, "EnumDSPRev", TypeDecl.Ref(id(4)))
        val anon = ast(4, null, TypeDecl.Enum(listOf("A" to 0L)))
        assertEquals(mapOf(id(4) to "EnumDSPRev"), anonymousTypedefTargetNames(map(typedef, anon)))
    }

    @Test fun refToNamedTypeDoesNotRename() {
        // `typedef Existing Alias;` — target already named; a plain alias, leave it.
        val typedef = ast(3, "Alias", TypeDecl.Ref(id(4)))
        assertEquals(
            emptyMap<GlobalTypeId, String>(),
            anonymousTypedefTargetNames(map(typedef, ast(4, "Existing", struct()))),
        )
    }
}
