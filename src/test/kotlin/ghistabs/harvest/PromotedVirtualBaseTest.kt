package ghistabs.harvest

import ghistabs.index.TypeGraph
import ghistabs.materialize.cpp.virtualBases
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.parse.TypeDecl
import ghistabs.test.dummyHarvester
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * gcc 4.2.1 (MinGW, `crypto_mi_test_gcc421*`, `xmltest_gcc421*`) spells bases as fields of bytes×64 bits,
 * virtual ones too, at their offset in the complete object (render-backlog §100).
 */
class PromotedVirtualBaseTest {
    private fun lsym(index: Int, name: String) = StabRecord(index, StabType.N_LSYM, 0, 0, 0L, name)

    private val harvest = dummyHarvester().second.harvest(
        listOf(
            StabRecord(0, StabType.N_SO, 0, 0, 0L, "crypto_mi_test.cpp"),
            lsym(1, "ios_base:T(0,709)=s112_vptr\$ios_base:(0,253),0,32;;"),
            lsym(2, "basic_ios<char,std::char_traits<char> >:T(0,128)=s136ios_base:(0,709),0,7168;;"),
            lsym(
                3,
                "basic_istream<char,std::char_traits<char> >:T(0,132)=s144" +
                    "basic_ios<char,std::char_traits<char> >:(0,128),64,8704;" +
                    "_vptr\$basic_istream:(0,253),0,32;_M_gcount:(0,123),32,32;;",
            ),
            lsym(
                4,
                "basic_ostream<char,std::char_traits<char> >:T(0,134)=s140" +
                    "basic_ios<char,std::char_traits<char> >:(0,128),32,8704;_vptr\$basic_ostream:(0,253),0,32;;",
            ),
            lsym(
                5,
                "basic_iostream<char,std::char_traits<char> >:T(0,136)=s148" +
                    "basic_istream<char,std::char_traits<char> >:(0,132),0,9216;" +
                    "basic_ostream<char,std::char_traits<char> >:(0,134),64,8960;;",
            ),
        ),
    )

    private fun bases(n: Int) =
        (harvest.types.getValue(GlobalTypeId(SourceFile.CUSource("crypto_mi_test.cpp"), n)).body as TypeDecl.Aggregate)
            .bases.map { it.offsetBits to it.isVirtual }

    @Test
    fun `a dynamic base beside the class's own vptr is virtual`() {
        bases(132) mustBe listOf(64L to true)
        bases(134) mustBe listOf(32L to true)
    }

    @Test
    fun `a base sharing the class's vptr is not`() {
        bases(128) mustBe listOf(0L to false)
        bases(136) mustBe listOf(0L to false, 64L to false)
    }

    /** render-backlog §101: `basic_ios` is reached through both `basic_istream` and `basic_ostream`. */
    @Test
    fun `a diamond's shared virtual base is one virtual base`() {
        val iostream = harvest.types.getValue(GlobalTypeId(SourceFile.CUSource("crypto_mi_test.cpp"), 136)).body
        TypeGraph(harvest).virtualBases(iostream as TypeDecl.Aggregate).map { it.offsetBits } mustBe listOf(64L)
    }
}
