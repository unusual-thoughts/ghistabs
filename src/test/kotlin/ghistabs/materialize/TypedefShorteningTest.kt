package ghistabs.materialize

import ghistabs.parse.canonTemplateName
import ghistabs.test.mustBe
import ghistabs.test.mustBeEmpty
import org.junit.jupiter.api.Test

/**
 * Pins [typedefShorteningRenames]: the pass that rewrites long templated datatype names onto shorter
 * typedef aliases, recursively inside other templates, longest target first. Uses a real std-string
 * spelling (gcc's `<char, …, … >` spacing) as fixtures.
 *
 * A name that is *wholly* an alias target is deliberately not renamed — the typedef carries that
 * spelling at every reference instead, so renaming it would collide with its own typedef. Each test
 * therefore asserts the nested rewrite and a null for the whole-name case.
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
        canonTemplateName(basicString) mustBe "basic_string<char,std::char_traits<char>,std::allocator<char>>"
        canonTemplateName("short unsigned int") mustBe "short unsigned int"
    }

    @Test
    fun `pass rewrites targets inside other templates and leaves whole-name matches alone`() {
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

        // The target itself is left alone — `string` is a typedef onto it, and references resolve
        // through that typedef rather than through a renamed struct.
        renames[basicString] mustBe null
        // Substring rewrite inside another template, with std:: prefix preserved.
        renames["list<std::basic_string<char, std::char_traits<char>, std::allocator<char> > >"] mustBe
            "list<std::string>"
        // `stringVec` is wholly StringVec's target, so it too is left to its typedef…
        renames[stringVec] mustBe null
        // …but longest-target-first still applies where it is nested: the map's argument matches
        // StringVec, not the inner vector<std::string,…>.
        renames["map<int, $stringVec >"] mustBe "map<int,StringVec>"
        // Non-templated / multi-word names are left alone (no whitespace-only renames).
        renames["int"] mustBe null
        renames["short unsigned int"] mustBe null
    }

    @Test
    fun `when several typedefs name one target the shortest alias wins`() {
        // libstdc++ aliases basic_string as string, _Value_type, _ValueType — string must win.
        val renames = typedefShorteningRenames(
            mapOf("_Value_type" to basicString, "string" to basicString, "_ValueType" to basicString),
            setOf(basicString, "list<std::basic_string<char, std::char_traits<char>, std::allocator<char> > >"),
        ).associate { it.from to it.to }
        renames["list<std::basic_string<char, std::char_traits<char>, std::allocator<char> > >"] mustBe
            "list<std::string>"
    }

    @Test
    fun `a readable alias beats shorter compiler-internal shorthands`() {
        // libstdc++ instantiation TUs emit `typedef basic_string<…> S` and `__string_type`; the raw
        // shortest-name rule would pick `S`. `string` must win over both.
        val renames = typedefShorteningRenames(
            mapOf("S" to basicString, "__string_type" to basicString, "string" to basicString),
            setOf("list<std::$basicString >"),
        ).associate { it.from to it.to }
        renames["list<std::$basicString >"] mustBe "list<std::string>"
    }

    @Test
    fun `a single-letter alias is still used when it is the only one`() {
        // The internal-name filter must fall back rather than skip the rename entirely.
        val renames = typedefShorteningRenames(mapOf("N" to "Node"), setOf("vector<Node>"))
            .associate { it.from to it.to }
        renames["vector<Node>"] mustBe "vector<N>"
    }

    @Test
    fun `a bare-identifier target matches only on identifier boundaries`() {
        // `Node`→`N` must rewrite `vector<Node>` but never a substring of `NodeList` / `TreeNode`.
        val renames = typedefShorteningRenames(
            mapOf("N" to "Node"),
            setOf("Node", "NodeList", "TreeNode", "vector<Node>", "vector<NodeList>"),
        ).associate { it.from to it.to }
        renames["Node"] mustBe null
        renames["vector<Node>"] mustBe "vector<N>"
        renames["NodeList"] mustBe null
        renames["TreeNode"] mustBe null
        renames["vector<NodeList>"] mustBe null
    }

    @Test
    fun `a typedef no shorter than its target produces no rename`() {
        val renames = typedefShorteningRenames(
            mapOf("LongAliasName" to "int", "Foo" to "Bar"),
            setOf("int", "Bar", "vector<int>", "vector<Bar>"),
        )
        renames.mustBeEmpty("no alias is strictly shorter than its target: $renames")
    }

    @Test
    fun `substitute rewrites a line of code without canonicalising its spacing`() {
        val s = TemplateNameShortener(mapOf("string" to "basic_string<char,std::char_traits<char>>"))
        s.substitute("f(basic_string<char,std::char_traits<char>> *a, int b) { return a > b; }") mustBe
            "f(string *a, int b) { return a > b; }"
        // shorten() canonicalises first, which on a code line closes up `a, int`, `a > b`, and — worst
        // — the space after the closing `>`, welding the declarator onto its type as `string*a`.
        s.shorten("f(basic_string<char,std::char_traits<char>> *a, int b) { return a > b; }") mustBe
            "f(string*a,int b) { return a>b; }"
    }
}
