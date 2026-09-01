package ghistabs.index

import ghidra.program.model.data.CategoryPath
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.harvest.*
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Struct.Field
import ghistabs.parse.TypeDecl.Struct.Method
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [TypeGraph.locateTypes] scope-recovery for **method-less** nested member types (`_Alloc_hider`,
 * `_Rep`, `sentry`). They carry no mangled method, so [demangledClassPath] can't scope them and the bare
 * leaf name collides char-vs-wchar under one header key. The resolver recovers the enclosing template two
 * ways — from the type's own `Outer::Inner` stab name, or from the struct that holds it by value — and
 * files it under that template's member category, the slot its qualified method-bearing sibling occupies.
 *
 * Headless (real GnuDemangler), like [EnclosingScopeTest]; the harvest is hand-built, no mocks.
 */
@Tag("integration")
class NestedScopeKeyTest : AbstractGhidraHeadlessIntegrationTest() {
    private val cu = SourceFile.CUSource("string-inst.cc")
    private var nextId = 1
    private fun id() = GlobalTypeId(cu, nextId++)

    private fun method(mangled: String) = Method<GlobalTypeId>(
        name = "m",
        mangled = mangled,
        signature = TypeDecl.Builtin(0),
        access = Access.PUBLIC,
        virt = VirtKind.NORMAL,
        isConst = false,
        isVolatile = false,
        vtableOffsetBits = null,
    )

    private fun field(name: String, type: GlobalTypeDecl) =
        Field(name, type, 0, 32, isStatic = false, access = Access.PUBLIC, mangled = null)

    private fun struct(
        methods: List<Method<GlobalTypeId>> = emptyList(),
        fields: List<Field<GlobalTypeId>> = emptyList(),
    ) = TypeDecl.Struct(
        kind = AggrKind.STRUCT,
        sizeBytes = 4L,
        bases = emptyList(),
        fields = fields,
        methods = methods,
        vptrBasetype = null,
    )

    private fun ast(id: GlobalTypeId, name: String?, body: GlobalTypeDecl) =
        Type(cu = cu, id = id, name = name, body = body)

    private val charString = "basic_string<char,std::char_traits<char>,std::allocator<char> >"
    private val wcharString = "basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t> >"

    @Test fun methodlessNestedStructScopedByContainingField() {
        // A method-bearing basic_string<char> establishes /std/string as its member category; the bare,
        // method-less _Alloc_hider is reachable only as basic_string's by-value `_M_dataplus` field.
        val full = ast(id(), charString, struct(methods = listOf(method("_ZNSs5clearEv"))))
        val hiderId = id()
        val hider = ast(hiderId, "_Alloc_hider", struct(fields = listOf(field("_M_p", TypeDecl.Builtin(0)))))
        val reduced = ast(id(), charString, struct(fields = listOf(field("_M_dataplus", TypeDecl.Ref(hiderId)))))

        val groups = indexOf(full, hider, reduced).let { it.types.locateTypes(it.hints) }
        val key = TypeLocation(CategoryPath("/std/string"), "_Alloc_hider")
        groups.must("expected $key in ${groups.keys}") { contains(key) }
        hiderId mustBeIn groups.getValue(key).members
    }

    @Test fun qualifiedNameScopesMethodlessNested() {
        // gcc emits `basic_ostream<char,…>::sentry` method-less in some CUs; the qualifier alone scopes it,
        // under the same member category the method-bearing ostream files members under (`So`→`ostream`).
        val ostream = "basic_ostream<char, std::char_traits<char> >"
        val full = ast(id(), ostream, struct(methods = listOf(method("_ZNSo5flushEv"))))
        val sentryId = id()
        val sentry = ast(sentryId, "$ostream::sentry", struct(fields = listOf(field("_M_ok", TypeDecl.Builtin(0)))))

        val groups = indexOf(full, sentry).let { it.types.locateTypes(it.hints) }
        val key = TypeLocation(CategoryPath("/std/ostream"), "sentry")
        groups.must("expected $key in ${groups.keys}") { contains(key) }
        sentryId mustBeIn groups.getValue(key).members
    }

    @Test fun charAndWcharVariantsGetDistinctKeys() {
        fun hiderKeyFor(strName: String, clearMangled: String, pointee: GlobalTypeDecl): TypeLocation {
            nextId = 1
            val full = ast(id(), strName, struct(methods = listOf(method(clearMangled))))
            val hiderId = id()
            val hider = ast(hiderId, "_Alloc_hider", struct(fields = listOf(field("_M_p", TypeDecl.Pointer(pointee)))))
            val reduced = ast(id(), strName, struct(fields = listOf(field("_M_dataplus", TypeDecl.Ref(hiderId)))))
            val located = indexOf(full, hider, reduced).let { it.types.locateTypes(it.hints) }
            return located.entries.first { hiderId in it.value.members }.key
        }

        val charKey = hiderKeyFor(charString, "_ZNSs5clearEv", TypeDecl.Builtin(2))
        val wcharKey = hiderKeyFor(wcharString, "_ZNSbIwSt11char_traitsIwESaIwEE5clearEv", TypeDecl.Builtin(21))
        charKey.name mustBe "_Alloc_hider"
        wcharKey.category.mustNotBe(charKey.category)
    }
}
