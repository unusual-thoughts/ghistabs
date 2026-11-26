package ghicpp.abi.itanium

import ghicpp.Access
import ghicpp.ClassBase
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

/**
 * [ItaniumClass.nonVirtualSize] on the shapes gcc lays: `CryptoMaterial`, a nearly empty virtual base, laid over the
 * vptr of `PublicKey`, the non-virtual base it is the primary base of, and `std::ios` laid past `std::ostream`.
 */
class ItaniumClassTest {
    private fun cls(name: String, bases: List<ClassBase> = emptyList(), virtualBases: List<ClassBase> = emptyList()) =
        ItaniumClass(null, name, emptyList(), bases, virtualBases)

    private fun ItaniumClass.at(offset: Long?) = ClassBase(this, false, Access.PUBLIC, offset)

    private fun ItaniumClass.virtualAt(offset: Long?) = ClassBase(this, true, Access.PUBLIC, offset)

    @Test
    fun `a virtual base over a non-virtual base's vptr does not end the non-virtual part`() {
        val material = cls("CryptoMaterial")
        val publicKey = cls("PublicKey", listOf(material.virtualAt(null)), listOf(material.virtualAt(0)))
        val asn1 = cls("ASN1Object")
        val x509 = cls("X509PublicKey", listOf(asn1.at(0), publicKey.at(4)), listOf(material.virtualAt(4)))
        val keyImpl = cls("DL_KeyImpl", listOf(x509.at(0)), listOf(material.virtualAt(4)))
        x509.nonVirtualSize mustBe null
        keyImpl.nonVirtualSize mustBe null
    }

    @Test
    fun `a virtual base past the non-virtual bases ends the non-virtual part`() {
        val ios = cls("ios")
        val ostream = cls("ostream", listOf(ios.virtualAt(null)), listOf(ios.virtualAt(4)))
        val ofstream = cls("ofstream", listOf(ostream.at(0)), listOf(ios.virtualAt(112)))
        ostream.nonVirtualSize mustBe 4L
        ofstream.nonVirtualSize mustBe 112L
    }
}
