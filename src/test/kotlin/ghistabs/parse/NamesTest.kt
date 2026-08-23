package ghistabs.parse

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class NamesTest {
    @Test
    fun `splits plain namespace chain`() {
        splitQualified("std::vector") mustBe listOf("std", "vector")
    }

    @Test
    fun `keeps inner scope-sep inside angle brackets together`() {
        splitQualified("std::map<std::string, int>") mustBe listOf("std", "map<std::string, int>")
    }

    @Test
    fun `handles deeply nested templates`() {
        val input = "std::basic_string<char, std::char_traits<char>, std::allocator<char>>::basic_string"

        splitQualified(input) mustBe listOf(
            "std",
            "basic_string<char, std::char_traits<char>, std::allocator<char>>",
            "basic_string",
        )
    }

    @Test
    fun `keeps scope-sep inside parens together`() {
        splitQualified("ns::f(std::pair<int, int>)") mustBe listOf("ns", "f(std::pair<int, int>)")
    }

    @Test
    fun `comparison operators inside template args don't break depth tracking`() {
        // Real gcc stabs may contain inner `<` / `>` only as template brackets,
        // not as comparison operators — gcc writes type expressions, not
        // value expressions. We only need depth tracking that survives
        // balanced templates.
        splitQualified("ns::less<int>::operator()") mustBe listOf("ns", "less<int>", "operator()")
    }

    @Test
    fun `empty leading separator collapses to single segment`() {
        splitQualified("::foo") mustBe listOf("foo")
    }

    @Test
    fun `single name returns itself`() {
        splitQualified("Foo") mustBe listOf("Foo")
    }

    @Test
    fun `empty string returns empty list`() {
        splitQualified("") mustBe emptyList()
    }
}
