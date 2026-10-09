package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.Demangler
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [Demangler.namespaces] states a member's class with its template arguments, conversion operators included.
 *
 * Names from crypto_mi_test_gcc421: `GetValueHelperClass` and `SecBlock` reach the scope key only
 * through members like these, and Ghidra demangles a conversion operator in a template into the bare
 * template name, which would put every instantiation in one `/CryptoPP/GetValueHelperClass` slot.
 */
@Tag("integration")
class DemanglerNamespacesIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private val helper = "GetValueHelperClass<CryptoPP::DL_GroupParameters<CryptoPP::Integer>," +
        "CryptoPP::DL_GroupParameters<CryptoPP::Integer>>"

    @Test
    fun aConversionOperatorInATemplateStatesItsClassWhole() {
        val operatorBool = "_ZNK8CryptoPP19GetValueHelperClassINS_18DL_GroupParametersINS_7IntegerEEES3_EcvbEv"
        Demangler.namespaces(operatorBool) mustBe listOf("CryptoPP", helper)
    }

    @Test
    fun anotherMemberOfTheSameTemplateStatesItAlike() {
        val callOperator = "_ZN8CryptoPP19GetValueHelperClassINS_18DL_GroupParametersINS_7IntegerEEES3_EclIS2_EERS4_" +
            "PKcMS3_KFRKT_vE"
        Demangler.namespaces(callOperator) mustBe listOf("CryptoPP", helper)
    }

    @Test
    fun aConversionOperatorOutsideATemplateStatesItsClass() {
        // `CryptoPP::Integer::operator bool() const`: nothing to strip.
        Demangler.namespaces("_ZNK8CryptoPP7IntegercvbEv") mustBe listOf("CryptoPP", "Integer")
    }
}
