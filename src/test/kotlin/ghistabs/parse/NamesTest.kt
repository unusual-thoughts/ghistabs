package ghistabs.parse

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class NamesTest {
    @Test
    fun `splits plain namespace chain`() {
        Assertions.assertEquals(listOf("std", "vector"), splitQualified("std::vector"))
    }

    @Test
    fun `keeps inner scope-sep inside angle brackets together`() {
        Assertions.assertEquals(
            listOf("std", "map<std::string, int>"),
            splitQualified("std::map<std::string, int>"),
        )
    }

    @Test
    fun `handles deeply nested templates`() {
        val input =
            "std::basic_string<char, std::char_traits<char>, std::allocator<char>>::basic_string"
        Assertions.assertEquals(
            listOf(
                "std",
                "basic_string<char, std::char_traits<char>, std::allocator<char>>",
                "basic_string",
            ),
            splitQualified(input),
        )
    }

    @Test
    fun `keeps scope-sep inside parens together`() {
        Assertions.assertEquals(
            listOf("ns", "f(std::pair<int, int>)"),
            splitQualified("ns::f(std::pair<int, int>)"),
        )
    }

    @Test
    fun `comparison operators inside template args don't break depth tracking`() {
        // Real gcc stabs may contain inner `<` / `>` only as template brackets,
        // not as comparison operators — gcc writes type expressions, not
        // value expressions. We only need depth tracking that survives
        // balanced templates.
        Assertions.assertEquals(
            listOf("ns", "less<int>", "operator()"),
            splitQualified("ns::less<int>::operator()"),
        )
    }

    @Test
    fun `empty leading separator collapses to single segment`() {
        Assertions.assertEquals(listOf("foo"), splitQualified("::foo"))
    }

    @Test
    fun `single name returns itself`() {
        Assertions.assertEquals(listOf("Foo"), splitQualified("Foo"))
    }

    @Test
    fun `empty string returns empty list`() {
        Assertions.assertEquals(emptyList<String>(), splitQualified(""))
    }

    @Test
    fun `collapses multiword builtin spellings the demangler underscores`() {
        Assertions.assertEquals("unsignedchar", collapseBuiltinSpelling("unsigned_char"))
        Assertions.assertEquals("longlongunsignedint", collapseBuiltinSpelling("long_long_unsigned_int"))
        Assertions.assertEquals(
            "SecBlock<unsignedint,CryptoPP::NullAllocator<unsignedint>>",
            collapseBuiltinSpelling("SecBlock<unsigned_int,CryptoPP::NullAllocator<unsigned_int>>"),
        )
    }

    @Test
    fun `leaves underscores that were never spaces alone`() {
        // Stripping all underscores collided 504 distinct names per fixture (`_off_t` vs `off_t`,
        // `MIDL_STUB_DESC` vs `_MIDL_STUB_DESC`) — only builtin-word runs may collapse.
        for (name in listOf("_off_t", "MIDL_STUB_DESC", "_MIDL_STUB_DESC", "__int_type", "__char_type", "DL_Base")) {
            Assertions.assertEquals(name, collapseBuiltinSpelling(name))
        }
    }
}
