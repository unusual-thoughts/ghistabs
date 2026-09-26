package ghistabs.parse

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class NamesTest {
    @Test
    fun `splits plain namespace chain`() {
        "std::vector".nameSegments mustBe listOf("std", "vector")
    }

    @Test
    fun `keeps inner scope-sep inside angle brackets together`() {
        "std::map<std::string, int>".nameSegments mustBe listOf("std", "map<std::string, int>")
    }

    @Test
    fun `handles deeply nested templates`() {
        val input = "std::basic_string<char, std::char_traits<char>, std::allocator<char>>::basic_string"

        input.nameSegments mustBe listOf(
            "std",
            "basic_string<char, std::char_traits<char>, std::allocator<char>>",
            "basic_string",
        )
    }

    @Test
    fun `keeps scope-sep inside parens together`() {
        "ns::f(std::pair<int, int>)".nameSegments mustBe listOf("ns", "f(std::pair<int, int>)")
    }

    @Test
    fun `comparison operators inside template args don't break depth tracking`() {
        // Real gcc stabs may contain inner `<` / `>` only as template brackets,
        // not as comparison operators — gcc writes type expressions, not
        // value expressions. We only need depth tracking that survives
        // balanced templates.
        "ns::less<int>::operator()".nameSegments mustBe listOf("ns", "less<int>", "operator()")
    }

    @Test
    fun `empty leading separator collapses to single segment`() {
        "::foo".nameSegments mustBe listOf("foo")
    }

    @Test
    fun `single name returns itself`() {
        "Foo".nameSegments mustBe listOf("Foo")
    }

    @Test
    fun `empty string returns empty list`() {
        "".nameSegments mustBe emptyList()
    }

    @Test
    fun `leaf keeps a qualified template argument whole`() {
        "Foo<ns::Bar>".leafName mustBe "Foo<ns::Bar>"
    }

    @Test
    fun `template name strips every segment's arguments`() {
        "A<int>::Inner".templateName mustBe "A::Inner"
        "std::vector<int, std::allocator<int> >".templateName mustBe "std::vector"
    }

    @Test
    fun `template leaf of a nested class is the nested class`() {
        "A<int>::Inner".templateLeaf mustBe "Inner"
        "std::vector<int>".templateLeaf mustBe "vector"
    }

    @Test
    fun `a nested class belongs to its outermost template`() {
        "A<int>::Inner".outermostTemplate mustBe "A"
        "std::vector<int>::iterator".outermostTemplate mustBe "std::vector"
        "allocator<wchar_t>::rebind<wchar_t>".outermostTemplate mustBe "allocator"
    }

    @Test
    fun `enclosing name keeps a template argument's own scope`() {
        "A<ns::B>::Inner".enclosingName mustBe "A<ns::B>"
        "Plain".enclosingName mustBe null
    }

    @Test
    fun `an operator's angle bracket is no template`() {
        "A::operator<".isTemplated mustBe false
        "A<int>::operator<".isTemplated mustBe true
        "Plain".isTemplated mustBe false
    }

    @Test
    fun `recognizes all three vptr field spellings gcc emits`() {
        isVptrFieldName($$"_vptr$Foo") mustBe true
        isVptrFieldName("_vptr.Bar") mustBe true
        isVptrFieldName("_vptr") mustBe true
        isVptrFieldName("m_member") mustBe false
    }
}
