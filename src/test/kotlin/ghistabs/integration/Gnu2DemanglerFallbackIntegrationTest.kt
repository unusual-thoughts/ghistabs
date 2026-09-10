package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.Demangler
import ghistabs.test.must
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [Demangler] reads gcc 2.x names as well as Itanium ones, and reads nothing else.
 *
 * The two back ends are disjoint: Ghidra's modern demangler answers `unknown demangling style 'gnu'`
 * for gcc 2.x, and the deprecated one decodes none of 5630 Itanium names on xmltest_gcc421. So the
 * fallback has to fire without displacing the primary, and the guard against a swap is the Itanium
 * case here.
 *
 * The gate matters as much as the fallback: the gcc 2.x back end accepts names that were never
 * mangled and returns the input less its punctuation, which on the Sun-compiler fixtures is 2052
 * such answers to zero real ones. `.bss` is the sentinel for that.
 */
@Tag("integration")
class Gnu2DemanglerFallbackIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private fun sig(mangled: String) = Demangler.of(mangled)?.signature

    @Test
    fun readsGcc2Names() {
        sig("__10CAllocator") mustBe "undefined CAllocator::CAllocator(void)"
        sig("_._10bad_typeid") mustBe "undefined bad_typeid::~bad_typeid(void)"
        sig("__10CDirectoryUs") mustBe "undefined CDirectory::CDirectory(unsigned short)"
        sig("TiXmlFOpen__FPCcT0") mustBe "undefined TiXmlFOpen(char const *,char const *)"
        sig("_9TiXmlBase.entity") mustBe "TiXmlBase::entity"
    }

    @Test
    fun stillReadsItanium() {
        sig("_ZN9TiXmlNode8SetValueEPKc") mustBe "undefined TiXmlNode::SetValue(char const *)"
        sig("__ZTV9exception") mustBe "exception::vtable"
    }

    @Test
    fun declinesNamesThatWereNeverMangled() {
        listOf(".bss", ".comment", ".data").forEach {
            Demangler.of(it).must("'$it' is a section name, not a mangled one") { this == null }
        }
    }
}
