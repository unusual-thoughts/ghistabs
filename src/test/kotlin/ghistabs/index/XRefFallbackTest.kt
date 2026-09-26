package ghistabs.index

import ghistabs.harvest.Type
import ghistabs.harvest.binding
import ghistabs.parse.*
import ghistabs.test.mustBe
import ghistabs.test.typesOf
import org.junit.jupiter.api.Test

/** `TypeGraph.byXRef`'s base-tag fallback, past a failed exact-name lookup. */
class XRefFallbackTest {
    private val cu = SourceFile.CUSource("s.cpp")

    private fun struct(n: Int, name: String, size: Long = 4L): Type {
        val body = TypeDecl.Aggregate<GlobalTypeId>(AggrKind.STRUCT, size, emptyList(), emptyList(), emptyList(), null)
        return Type(cu = cu, id = GlobalTypeId(cu, n), named = binding(name, body), body = body)
    }

    private fun resolve(tag: String, vararg defs: Type) =
        typesOf(*defs).byXRef(TypeDecl.XRef(AggrKind.STRUCT, tag))?.name

    @Test
    fun `a bare tag takes the one size its instantiations agree on`() {
        resolve("basic_istream", struct(1, "basic_istream<char,std::char_traits<char> >")) mustBe
            "basic_istream<char,std::char_traits<char> >"
    }

    // locale_test gcc 3.4.5: `xsbasic_string<wchar_t,…>:` took `basic_string<char,…>`, both 4 bytes.
    @Test
    fun `a templated tag never takes another instantiation`() {
        resolve("basic_string<wchar_t>", struct(1, "basic_string<char>")) mustBe null
    }

    @Test
    fun `a templated tag takes its own instantiation spelled differently`() {
        resolve("vector<vector<int> >", struct(1, "vector<vector<int>>")) mustBe "vector<vector<int>>"
    }
}
