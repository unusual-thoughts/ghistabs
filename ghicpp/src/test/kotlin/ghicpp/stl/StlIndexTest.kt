package ghicpp.stl

import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class StlIndexTest {
    private fun key(vararg path: String) = StlIndex.key(path.toList())

    @Test
    fun `the demangler's and the DWARF importer's spellings of one class share a key`() {
        key("std", "pair<int_const,int>") mustBe key("std", "pair<int_const,_int>")
        key("std", "map<int,int,std::less<int>,std::allocator<std::pair<int_const,int>>>") mustBe
            key("std", "map<int,_int,_std::less<int>,_std::allocator<std::pair<const_int,_int>_>_>")
    }

    @Test
    fun `a const pointer and a plain one keep their keys apart`() {
        (
            key("__gnu_cxx", "__normal_iterator<char_const*,std::string>") ==
                key("__gnu_cxx", "__normal_iterator<char*,std::string>")
            ) mustBe
            false
        key("__gnu_cxx", "__normal_iterator<char_const*,std::string>") mustBe
            key(
                "__gnu_cxx",
                "__normal_iterator<const_char*,_std::basic_string<char,_std::char_traits<char>,_std::allocator<char>_>_>",
            )
    }

    @Test
    fun `a template argument's integer suffix is left out`() {
        key("std", "_Head_base<0ul,int*,false>") mustBe key("std", "_Head_base<0,_int*,_false>")
        key("std", "array<int,4ul>") mustBe key("std", "array<int,_4>")
    }

    @Test
    fun `an alias the demangler puts for a library template is written out, in either ABI`() {
        val cow = "basic_string<char,_std::char_traits<char>,_std::allocator<char>_>"
        key("std", "string") mustBe key("std", cow)
        key("std", "__cxx11", "string") mustBe key("std", "__cxx11", cow)
        key("__gnu_cxx", "__aligned_membuf<std::string>") mustBe key("__gnu_cxx", "__aligned_membuf<std::$cow>")
        key("__gnu_cxx", "__aligned_membuf<std::pair<std::__cxx11::string_const,void*>>") mustBe
            key("__gnu_cxx", "__aligned_membuf<std::pair<const_std::__cxx11::${cow}_,_void*>_>")
        key("std", "__cxx11", "wstringstream") mustBe
            key(
                "std",
                "__cxx11",
                "basic_stringstream<wchar_t,_std::char_traits<wchar_t>,_std::allocator<wchar_t>_>",
            )
    }

    @Test
    fun `a name that only starts like an alias is left alone`() {
        (
            key("std", "stringstream_base") ==
                key("std", "basic_string<char,_std::char_traits<char>,_std::allocator<char>_>stream_base")
            ) mustBe
            false
        (key("std", "string") == key("std", "__cxx11", "string")) mustBe false
    }
}
