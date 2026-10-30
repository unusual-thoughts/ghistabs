package ghistabs.cpp.abi.itanium

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** [ghistabs.cpp.abi.ItaniumStructor.of] asks Ghidra's demangler, which needs the Ghidra application up. */
@Tag("integration")
class ItaniumStructorIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `structor variants are read where the demangler places them`() {
        ItaniumStructor.of("_ZN3FooC1Ev") mustBe ItaniumStructor.COMPLETE_CTOR
        ItaniumStructor.of("__ZN3FooC2ERKS_") mustBe ItaniumStructor.BASE_CTOR
        ItaniumStructor.of("_ZN2ns3FooD0Ev") mustBe ItaniumStructor.DELETING_DTOR
        ItaniumStructor.of("_ZNSt9exceptionD2Ev") mustBe ItaniumStructor.BASE_DTOR
        ItaniumStructor.of("_ZN1BCI21AEi") mustBe ItaniumStructor.BASE_INHERITING_CTOR
        ItaniumStructor.of("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_") mustBe
            ItaniumStructor.COMPLETE_CTOR
        ItaniumStructor.of("_ZN3FooILi1EN2ns3BarEEC4Ev") mustBe ItaniumStructor.UNIFIED_CTOR
        ItaniumStructor.of("_ZN3FooB5cxx11D1Ev") mustBe ItaniumStructor.COMPLETE_DTOR
        // `C1` inside a class's spelling, or in an argument, isn't the variant.
        ItaniumStructor.of("_ZN3AC13getEv") mustBe null
        ItaniumStructor.of("_ZN3Foo3setEN2C1E") mustBe null
        ItaniumStructor.of("_Z3fooC1v") mustBe null
        ItaniumStructor.of("__ct__3Foo") mustBe null
    }
}
