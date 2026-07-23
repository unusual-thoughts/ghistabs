package ghistabs.harvest

import ghidra.program.model.data.CategoryPath
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.parse.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [TypeAst.enclosingScope] / [demangledClassPath] over Ghidra's GnuDemangler. Headless (not a pure unit)
 * because the demangler needs an initialised Ghidra Application — it needs no Program or Address, but it
 * is not a plain library call. Real, complete Itanium manglings; the `Ss` abbreviation is what makes the
 * leaf diverge from the stabs spelling (`std::string`, not `std::basic_string<char,…>`).
 */
@Tag("integration")
class EnclosingScopeTest : AbstractGhidraHeadlessIntegrationTest() {
    private val cu = SourceFile.CUSource("lexstream.cpp")

    private fun method(mangled: String?) = MethodDecl<GlobalTypeId>(
        name = "m",
        mangled = mangled,
        signature = TypeDecl.Builtin(0),
        access = Access.PUBLIC,
        virt = VirtKind.NORMAL,
        isConst = false,
        isVolatile = false,
        vtableOffsetBits = null,
    )

    private fun struct(vararg methods: MethodDecl<GlobalTypeId>) = TypeDecl.Struct<GlobalTypeId>(
        rawKind = AggrKind.STRUCT,
        sizeBytes = 4L,
        bases = emptyList(),
        fields = emptyList(),
        methods = methods.toList(),
        vptrBasetype = null,
    )

    private fun ast(name: String?, body: TypeDecl<GlobalTypeId>) =
        TypeAst(cu = cu, id = GlobalTypeId(cu, 1), name = name, body = body)

    @Test fun namespacedClassDropsOwnLeaf() {
        // _ZNSs5clearEv → std::string::clear(); `Ss` expands to the short `string`, not basic_string<…>.
        val scope = ast("basic_string<char>", struct(method("_ZNSs5clearEv"))).enclosingScope()
        assertEquals(listOf("std"), scope)
        assertEquals(CategoryPath("/std"), scopeCategory(scope!!))
    }

    @Test fun globalClassScopeIsRoot() {
        // _ZN10ThisStream5ParseEv → bouniaf::Parse(); a global class has the empty enclosing scope.
        val scope = ast("ThisStream", struct(method("_ZN10ThisStream5ParseEv"))).enclosingScope()
        assertEquals(emptyList<String>(), scope)
        assertEquals(CategoryPath.ROOT, scopeCategory(scope!!))
    }

    @Test fun nestedClassKeepsOuterScope() {
        // _ZN3Foo3Bar1fEv → Foo::Bar::f(); the class's own leaf (Bar) drops, its outer scope stays.
        val scope = ast("Bar", struct(method("_ZN3Foo3Bar1fEv"))).enclosingScope()
        assertEquals(listOf("Foo"), scope)
        assertEquals(CategoryPath("/Foo"), scopeCategory(scope!!))
    }

    @Test fun firstDemanglableMethodWins() {
        val scope = ast("X", struct(method(null), method("_ZNSs5clearEv"))).enclosingScope()
        assertEquals(listOf("std"), scope)
    }

    @Test fun methodlessTypeHasNoScope() {
        assertNull(ast("PlainC", struct()).enclosingScope())
    }

    @Test fun nonStructBodyHasNoScope() {
        assertNull(ast("anEnum", TypeDecl.Enum(listOf("A" to 0L))).enclosingScope())
    }

    @Test fun unmangleableMethodHasNoScope() {
        assertNull(ast("X", struct(method("not_a_mangle"))).enclosingScope())
    }
}
