package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.Demangler
import ghistabs.LoadedProgram
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.abi.vtableRecord
import ghistabs.entrypoints.RttiSymbolsAnalyzer
import ghistabs.loadProgram
import ghistabs.runTransaction
import ghistabs.test.defaultContext
import ghistabs.test.importAndAnalyze
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.MethodSource
import java.io.File
import java.util.stream.Stream

/**
 * A stripped twin finds its vtables where the unstripped one's symbols put them (§99). The two link
 * `.rdata` byte for byte; `_ZTV9TiXmlNode` is at 0x492400 there, and `_ZTVSd` at 0x492700, one vbase
 * offset ahead of its `offset_to_top` and with three construction vtables carrying `Sd`'s typeinfo too.
 */
@Tag("integration")
class RttiSymbolsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    /** By the analyzer alone, or with a stabs import after it. */
    @ParameterizedTest
    @CsvSource(
        "0x492400, 0x492408, true",
        "0x492700, 0x49270c, true",
        "0x492400, 0x492408, false",
        "0x492700, 0x49270c, false",
    )
    fun `a stripped binary's vtable is found through its typeinfo`(
        start: String,
        addressPoint: String,
        analyzer: Boolean,
    ) {
        val fixture = "xmltest_gcc421_fullstabs_stripped.exe"
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        if (analyzer) {
            program.runTransaction("rtti-symbols") {
                RttiSymbolsAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
            }
        } else {
            program.defaultContext().importAndAnalyze()
        }

        val at = program.addressFactory.defaultAddressSpace.getAddress(start)
        val named = program.symbolTable.getSymbols(at)
            .filter { it.source != SourceType.DEFAULT }
            .map { it.name }
        val vtable = named.firstOrNull { it == ClassNaming.VTABLE || it.startsWith("_ZTV") }
        checkNotNull(vtable) { "no vtable at $at: $named" }
        program.vtableRecord(at).addressPoint.toString() mustBe addressPoint.removePrefix("0x").padStart(8, '0')
    }

    /**
     * Every VTT and construction vtable the unstripped twin names, the stripped one gets back from its VTTs,
     * at the same address and nothing else: the twins link `.rdata` byte for byte. Compared demangled: the
     * `_ZTC` names put back spell the base out in full where gcc's substitute what the class already said
     * (`_ZTCSt13basic_fstreamIwSt11char_traitsIwEE0_St13basic_istreamIwS1_E`).
     */
    @ParameterizedTest
    @MethodSource("strippedTwins")
    fun `a stripped binary's VTTs and construction vtables are found through its typeinfo`(stripped: String) {
        val twin = stripped.replace("_stripped", "")
        fun File.vttLabels(analyze: Boolean) = loadProgram(this).use { loaded ->
            val program = loaded.program
            if (analyze) {
                program.runTransaction("rtti-symbols") {
                    RttiSymbolsAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
                }
            }
            program.symbolTable.getAllSymbols(false)
                .map { it.address.toString() to it.name.substringAfter("_ZT", "").let { n -> "_ZT$n" } }
                .filter { (_, name) -> name.startsWith("_ZTT") || name.startsWith("_ZTC") }
                .map { (at, name) -> at to (Demangler.of(name)?.originalDemangled ?: name) }
                .toSet()
        }
        val expected = File("src/test/resources/binaries/$twin").vttLabels(analyze = false)
        assumeTrue(expected.isNotEmpty(), "$twin has no VTT")
        File("src/test/resources/binaries/$stripped").vttLabels(analyze = true) mustBe expected
    }

    companion object {
        @JvmStatic
        fun strippedTwins(): Stream<String> = Fixtures.all()
            .filter {
                it.contains("_stripped") &&
                    File("src/test/resources/binaries/${it.replace("_stripped", "")}").exists()
            }
    }
}
