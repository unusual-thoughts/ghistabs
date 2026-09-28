package ghistabs.harvest

import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.test.dummyHarvester
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * gcc 12 C defines `typedef struct {…} SpinnerData;` at its first use and names it afterwards
 * (`box2d_tests`, render-backlog §85). The struct is where the typedef is, not where it was first used.
 */
class LateTypedefDatingTest {
    @Test
    fun `a struct named by a later typedef takes the typedef's line`() {
        val (sink, harvester) = dummyHarvester()
        val harvest = harvester.harvest(
            listOf(
                StabRecord(0, StabType.N_SO, 0, 0, 0L, "spinner.c"),
                StabRecord(1, StabType.N_LSYM, 0, 0, 0L, "long unsigned int:t(0,11)=r(0,11);0;-1;"),
                StabRecord(2, StabType.N_GSYM, 0, 40, 0L, "g_spinnerData:G(0,77)=(0,78)=s8spinnerId:(0,11),0,64;;"),
                StabRecord(3, StabType.N_LSYM, 0, 12, 0L, "SpinnerData:t(0,77)"),
            ),
        )

        sink.parseErrors mustBe 0
        val cu = SourceFile.CUSource("spinner.c")
        val typedef = harvest.types.getValue(GlobalTypeId(cu, 77))
        val struct = harvest.types.getValue(GlobalTypeId(cu, 78))
        struct.name mustBe "SpinnerData"
        typedef.line mustBe 12
        struct.line mustBe 12
        struct.sourceFile mustBe typedef.sourceFile
    }
}
