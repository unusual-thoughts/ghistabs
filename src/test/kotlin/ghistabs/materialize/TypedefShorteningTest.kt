package ghistabs.materialize

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pins [typedefShorteningRenames]: the pass that collapses long templated datatype names onto
 * shorter typedef aliases, recursively inside other templates, longest target first. Uses the
 * real bouniaf std-string spelling (gcc's `<char, …, … >` spacing) as fixtures.
 */
class TypedefShorteningTest {
    // gcc's DTM spelling — note spaces after commas and before the closing `>`.
    private val basicString = "basic_string<char, std::char_traits<char>, std::allocator<char> >"
    private val stringVec =
        "vector<std::basic_string<char, std::char_traits<char>, std::allocator<char> >, " +
            "std::allocator<std::basic_string<char, std::char_traits<char>, std::allocator<char> > > >"

    private val aliases = mapOf("string" to basicString, "StringVec" to stringVec)

    @Test
    fun `canonical spelling strips whitespace only around template punctuation`() {
        assertEquals(
            "basic_string<char,std::char_traits<char>,std::allocator<char>>",
            canonTemplateName(basicString),
        )
        assertEquals("short unsigned int", canonTemplateName("short unsigned int"))
    }

    @Test
    fun `pass renames target types and rewrites them inside other templates`() {
        val names = setOf(
            basicString,
            stringVec,
            "list<std::basic_string<char, std::char_traits<char>, std::allocator<char> > >",
            "map<int, $stringVec >",
            "int",
            "short unsigned int",
        )
        val renames = typedefShorteningRenames(aliases, names).associate { it.from to it.to }
        renames.forEach { (from, to) -> println("$from\n  -> $to") }

        // Target itself collapses to its alias.
        assertEquals("string", renames[basicString])
        // Substring rewrite inside another template, with std:: prefix preserved.
        assertEquals(
            "list<std::string>",
            renames["list<std::basic_string<char, std::char_traits<char>, std::allocator<char> > >"],
        )
        // Longest target wins: the whole vector matches StringVec, not vector<std::string,…>.
        assertEquals("StringVec", renames[stringVec])
        assertEquals("map<int,StringVec>", renames["map<int, $stringVec >"])
        // Non-templated / multi-word names are left alone (no whitespace-only renames).
        assertNull(renames["int"])
        assertNull(renames["short unsigned int"])
    }

    @Test
    fun `when several typedefs name one target the shortest alias wins`() {
        // libstdc++ aliases basic_string as string, _Value_type, _ValueType — string must win.
        val renames = typedefShorteningRenames(
            mapOf("_Value_type" to basicString, "string" to basicString, "_ValueType" to basicString),
            setOf(basicString, "list<std::basic_string<char, std::char_traits<char>, std::allocator<char> > >"),
        ).associate { it.from to it.to }
        assertEquals("string", renames[basicString])
        assertEquals(
            "list<std::string>",
            renames["list<std::basic_string<char, std::char_traits<char>, std::allocator<char> > >"],
        )
    }

    @Test
    fun `a bare-identifier target matches only on identifier boundaries`() {
        // `Node`→`N` must rewrite `vector<Node>` but never a substring of `NodeList` / `TreeNode`.
        val renames = typedefShorteningRenames(
            mapOf("N" to "Node"),
            setOf("Node", "NodeList", "TreeNode", "vector<Node>", "vector<NodeList>"),
        ).associate { it.from to it.to }
        assertEquals("N", renames["Node"])
        assertEquals("vector<N>", renames["vector<Node>"])
        assertNull(renames["NodeList"])
        assertNull(renames["TreeNode"])
        assertNull(renames["vector<NodeList>"])
    }

    @Test
    fun `a typedef no shorter than its target produces no rename`() {
        val renames = typedefShorteningRenames(
            mapOf("LongAliasName" to "int", "Foo" to "Bar"),
            setOf("int", "Bar", "vector<int>", "vector<Bar>"),
        )
        assertTrue(renames.isEmpty(), "no alias is strictly shorter than its target: $renames")
    }
}
