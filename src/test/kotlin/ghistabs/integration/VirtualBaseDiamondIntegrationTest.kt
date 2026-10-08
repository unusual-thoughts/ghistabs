package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.StabsImporter
import ghistabs.materialize.cpp.virtualBaseStructs
import ghistabs.materialize.cpp.virtualBases
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.parse.TypeDecl
import ghistabs.test.defaultContext
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * render-backlog §101: `basic_iostream` reaches `basic_ios` through both `basic_istream` and `basic_ostream`
 * (gcc 4.2.1's pseudo-field bases, promoted per §100). Two virtual edges, one virtual base.
 */
@Tag("integration")
class VirtualBaseDiamondIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".text", "0x400000", 1024)
        builder.createMemory(".stab", "0x402000", 4)
        builder.createMemory(".stabstr", "0x403000", 4)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun aDiamondsSharedVirtualBaseIsOneStruct() {
        val stabs = listOf(
            "int:t(0,1)=r(0,1);-2147483648;2147483647;",
            "__vtbl_ptr_type:t(0,252)=*(0,1)",
            "x:t(0,253)=*(0,252)",
            "ios_base:T(0,709)=s112_vptr\$ios_base:(0,253),0,32;;",
            "basic_ios<char,std::char_traits<char> >:T(0,128)=s136ios_base:(0,709),0,7168;;",
            "basic_istream<char,std::char_traits<char> >:T(0,132)=s144" +
                "basic_ios<char,std::char_traits<char> >:(0,128),64,8704;" +
                "_vptr\$basic_istream:(0,253),0,32;_M_gcount:(0,1),32,32;;",
            "basic_ostream<char,std::char_traits<char> >:T(0,134)=s140" +
                "basic_ios<char,std::char_traits<char> >:(0,128),32,8704;_vptr\$basic_ostream:(0,253),0,32;;",
            "basic_iostream<char,std::char_traits<char> >:T(0,136)=s148" +
                "basic_istream<char,std::char_traits<char> >:(0,132),0,9216;" +
                "basic_ostream<char,std::char_traits<char> >:(0,134),64,8960;;",
        )
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "crypto_mi_test.cpp")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val artifacts = StabsImporter(
            builder.program.defaultContext(),
        ).runOnRecords(StabReader.Result(records)).artifacts!!
        val iostream = artifacts.harvest.types.values.single { it.name?.startsWith("basic_iostream") == true }
            .body as TypeDecl.Aggregate

        artifacts.types.virtualBases(iostream).size mustBe 2
        artifacts.registry.virtualBaseStructs(iostream).map { (_, dt) -> dt?.name } mustBe
            listOf("basic_ios<char,std::char_traits<char>>")
    }
}
