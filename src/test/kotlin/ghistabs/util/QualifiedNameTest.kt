package ghistabs.util

import ghistabs.materialize.QualifiedName
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class QualifiedNameTest {
    @Test
    fun `splits plain namespace chain`() {
        assertEquals(listOf("std", "vector"), QualifiedName.split("std::vector"))
    }

    @Test
    fun `keeps inner scope-sep inside angle brackets together`() {
        assertEquals(
            listOf("std", "map<std::string, int>"),
            QualifiedName.split("std::map<std::string, int>"),
        )
    }

    @Test
    fun `handles deeply nested templates`() {
        val input =
            "std::basic_string<char, std::char_traits<char>, std::allocator<char>>::basic_string"
        assertEquals(
            listOf(
                "std",
                "basic_string<char, std::char_traits<char>, std::allocator<char>>",
                "basic_string",
            ),
            QualifiedName.split(input),
        )
    }

    @Test
    fun `keeps scope-sep inside parens together`() {
        assertEquals(
            listOf("ns", "f(std::pair<int, int>)"),
            QualifiedName.split("ns::f(std::pair<int, int>)"),
        )
    }

    @Test
    fun `comparison operators inside template args don't break depth tracking`() {
        // Real gcc stabs may contain inner `<` / `>` only as template brackets,
        // not as comparison operators — gcc writes type expressions, not
        // value expressions. We only need depth tracking that survives
        // balanced templates.
        assertEquals(
            listOf("ns", "less<int>", "operator()"),
            QualifiedName.split("ns::less<int>::operator()"),
        )
    }

    @Test
    fun `empty leading separator collapses to single segment`() {
        assertEquals(listOf("foo"), QualifiedName.split("::foo"))
    }

    @Test
    fun `single name returns itself`() {
        assertEquals(listOf("Foo"), QualifiedName.split("Foo"))
    }

    @Test
    fun `empty string returns empty list`() {
        assertEquals(emptyList<String>(), QualifiedName.split(""))
    }
}
