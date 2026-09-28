package ghistabs.harvest

import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.test.dummyHarvester
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * gcc 10+ define a base type inline at its first use and name it afterwards with a bodiless
 * `name:t(id)` (`hello_elf_gcc10`, render-backlog §78). That name is the builtin's.
 */
class LateBuiltinNameTest {
    private fun lsym(index: Int, name: String) = StabRecord(index, StabType.N_LSYM, 0, 0, 0L, name)

    @Test
    fun `a bodiless record names the builtin its id already defined`() {
        val (sink, harvester) = dummyHarvester()
        val harvest = harvester.harvest(
            listOf(
                StabRecord(0, StabType.N_SO, 0, 0, 0L, "hello.cc"),
                lsym(1, "Word:Tt(0,148)=u4b:(0,149)=ar(0,64);0;3;(0,150)=@s8;r(0,150);0;255;,0,32;;"),
                lsym(2, "unsigned char:t(0,150)"),
                lsym(3, "u8:t(0,164)=(0,150)"),
                lsym(4, "i64:t(0,165)=(0,166)=@s64;r(0,166);01000000000000000000000;00777777777777777777777;"),
                lsym(5, "long long int:t(0,166)"),
            ),
        )

        sink.parseErrors mustBe 0
        val cu = SourceFile.CUSource("hello.cc")
        harvest.types[GlobalTypeId(cu, 150)]?.name mustBe "unsigned char"
        harvest.types[GlobalTypeId(cu, 166)]?.name mustBe "long long int"
    }
}
