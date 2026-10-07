package ghistabs.materialize.cpp.abi

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** [StructorVariant.of] asks Ghidra's demangler, which needs the Ghidra application up. */
@Tag("integration")
class StructorVariantIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `structor variants are read where the demangler places them`() {
        StructorVariant.of("_ZN3FooC1Ev") mustBe StructorVariant.COMPLETE_CTOR
        StructorVariant.of("__ZN3FooC2ERKS_") mustBe StructorVariant.BASE_CTOR
        StructorVariant.of("_ZN2ns3FooD0Ev") mustBe StructorVariant.DELETING_DTOR
        StructorVariant.of("_ZNSt9exceptionD2Ev") mustBe StructorVariant.BASE_DTOR
        StructorVariant.of("_ZN1BCI21AEi") mustBe StructorVariant.BASE_INHERITING_CTOR
        StructorVariant.of("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_") mustBe
            StructorVariant.COMPLETE_CTOR
        StructorVariant.of("_ZN3FooILi1EN2ns3BarEEC4Ev") mustBe StructorVariant.UNIFIED_CTOR
        StructorVariant.of("_ZN3FooB5cxx11D1Ev") mustBe StructorVariant.COMPLETE_DTOR
        // `C1` inside a class's spelling, or in an argument, isn't the variant.
        StructorVariant.of("_ZN3AC13getEv") mustBe null
        StructorVariant.of("_ZN3Foo3setEN2C1E") mustBe null
        StructorVariant.of("_Z3fooC1v") mustBe null
        StructorVariant.of("__ct__3Foo") mustBe null
    }
}
