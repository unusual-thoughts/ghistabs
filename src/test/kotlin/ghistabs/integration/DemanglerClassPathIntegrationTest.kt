package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.Demangler
import ghistabs.test.mustBe
import ghistabs.test.mustBeEmpty
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [Demangler.classPath] states a member's class only where Ghidra's demangler keeps it whole.
 *
 * Names from crypto_mi_test_gcc421: `GetValueHelperClass` and `SecBlock` reach the scope key only
 * through members like these, and the conversion operator's template-stripped namespace put every
 * instantiation in one `/CryptoPP/GetValueHelperClass` slot.
 */
@Tag("integration")
class DemanglerClassPathIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private val helper = "GetValueHelperClass<CryptoPP::DL_GroupParameters<CryptoPP::Integer>," +
        "CryptoPP::DL_GroupParameters<CryptoPP::Integer>>"

    @Test
    fun aConversionOperatorInATemplateStatesNoClass() {
        val operatorBool = "_ZNK8CryptoPP19GetValueHelperClassINS_18DL_GroupParametersINS_7IntegerEEES3_EcvbEv"
        Demangler.namespaces(operatorBool) mustBe listOf("CryptoPP", "GetValueHelperClass")
        Demangler.classPath(operatorBool).mustBeEmpty("the template arguments were stripped")
    }

    @Test
    fun anotherMemberOfTheSameTemplateStatesItWhole() {
        val callOperator = "_ZN8CryptoPP19GetValueHelperClassINS_18DL_GroupParametersINS_7IntegerEEES3_EclIS2_EERS4_" +
            "PKcMS3_KFRKT_vE"
        Demangler.classPath(callOperator) mustBe listOf("CryptoPP", helper)
    }

    @Test
    fun aConversionOperatorOutsideATemplateStillStatesItsClass() {
        // `CryptoPP::Integer::operator bool() const`: nothing to strip.
        Demangler.classPath("_ZNK8CryptoPP7IntegercvbEv") mustBe listOf("CryptoPP", "Integer")
    }
}
