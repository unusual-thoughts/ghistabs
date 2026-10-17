package ghistabs.integration

import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.loadProgram
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.vtableRecord
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.File

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

    @ParameterizedTest
    @CsvSource("0x492400, 0x492408", "0x492700, 0x49270c")
    fun `a stripped binary's vtable is found through its typeinfo`(start: String, addressPoint: String) {
        val fixture = "xmltest_gcc421_fullstabs_stripped.exe"
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        program.defaultContext().import()

        val at = program.addressFactory.defaultAddressSpace.getAddress(start)
        val named = program.symbolTable.getSymbols(at)
            .filter { it.source != SourceType.DEFAULT }
            .map { it.name }
        val vtable = named.firstOrNull { it == ClassNaming.VTABLE || it.startsWith("_ZTV") }
        checkNotNull(vtable) { "no vtable at $at: $named" }
        program.vtableRecord(at).addressPoint.toString() mustBe addressPoint.removePrefix("0x").padStart(8, '0')
    }
}
