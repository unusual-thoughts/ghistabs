package ghicpp.stl

import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class StlApplierTest {
    @Test
    fun `untagged drops the keyword before each class argument`() {
        StlApplier.untagged(
            "std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>",
        ) mustBe "std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>_>"
    }

    @Test
    fun `untagged leaves names that only contain a keyword`() {
        StlApplier.untagged("std::pair<my_struct_t,subclass_x>") mustBe "std::pair<my_struct_t,subclass_x>"
    }
}
