package ghistabs.integration

import ghidra.program.model.data.Array
import ghidra.program.model.data.Undefined
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.loadProgram
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * `features/reloc.cc` left as an ELF relocatable (`g++ -gstabs+ -c`), where every addressed stab is 0
 * in the file plus a `.rel.stab` entry: i386 REL with the section offset in place (`zeroed` is
 * `.bss`+4), x86-64 RELA with it in the addend. Ghidra applies those against the load address, so the
 * stabs must be placed as they read, with no ELF image-base fixup on top.
 */
@Tag("integration")
class RelocatableObjectIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program

    private fun load(name: String) {
        assumeTrue(Fixtures.accepts(name), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/features/$name"))
        program.defaultContext().import()
    }

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @ValueSource(strings = ["reloc_elf_gcc295.o", "reloc_elf64_gcc12.o"])
    fun `functions get their stabs signature`(fixture: String) {
        load(fixture)

        mapOf("bump" to "by", "total" to "n").forEach { (name, param) ->
            val func = checkNotNull(program.functionManager.getFunctions(true).firstOrNull { name in it.name }) {
                "$name not found"
            }
            func.signatureSource mustBe SourceType.IMPORTED
            func.parameters.map { it.name } mustBe listOf(param)
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["reloc_elf_gcc295.o", "reloc_elf64_gcc12.o"])
    fun `statics are typed where their section put them`(fixture: String) {
        load(fixture)

        for (name in listOf("counter", "zeroed", "calls", "table")) {
            val symbols = program.symbolTable.getSymbols(name).toList()
            symbols.mustNotBeEmpty("no symbol $name")
            symbols.forEach { symbol ->
                val dataType = checkNotNull(program.listing.getDataAt(symbol.address)) {
                    "$name at ${symbol.address} holds no data"
                }.dataType
                dataType.mustNot("$name at ${symbol.address} left untyped") { Undefined.isUndefined(this) }
                if (name == "table") {
                    dataType.must("table should be short[4], got ${dataType.name}") {
                        this is Array && numElements == 4 && elementLength == 2
                    }
                }
            }
        }
    }
}
