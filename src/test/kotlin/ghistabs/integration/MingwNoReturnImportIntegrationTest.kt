package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.listing.Function
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.entrypoints.markNoReturn
import ghistabs.runTransaction
import ghistabs.test.must
import ghistabs.test.mustNot
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * msvcrt's `_assert` as a MinGW build imports it: an external the PE loader names `MSVCRT.DLL::assert`
 * (original name `_assert`), the `__assert` stub that thunks to it, and a caller that ends in the call:
 *
 * ```
 * __assert:  jmp dword ptr [__imp___assert]
 * fails:     call __assert
 * ```
 */
@Tag("integration")
class MingwNoReturnImportIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun mingwAssertNeverReturns() {
        build("gcc")
        mark()
        external().must("MSVCRT.DLL::assert is noreturn under MinGW") { hasNoReturn() }
        function(STUB).must("the __assert stub is noreturn through its thunk") { hasNoReturn() }
        function(CALLER).must("a function ending in call __assert is noreturn") { hasNoReturn() }
    }

    @Test
    fun msvcAssertKeepsGhidrasReading() {
        build("windows")
        mark()
        external().mustNot("MSVC's _assert can return") { hasNoReturn() }
        function(CALLER).mustNot("nothing makes its caller noreturn") { hasNoReturn() }
    }

    private fun build(compiler: String) {
        builder = ProgramBuilder("mingwassert", ProgramBuilder._X86, compiler, this)
        builder.createMemory(".text", "0x400000", 0x100)
        val assert = builder.createExternalFunction(null, "MSVCRT.DLL", "assert", "_assert")
        builder.setBytes(STUB, "ff 25 00 10 40 00", true)
        builder.setBytes(CALLER, "e8 eb ff ff ff", true)
        builder.createFunction(STUB)
        builder.createFunction(CALLER)
        program.runTransaction("thunk __assert") { function(STUB).setThunkedFunction(assert.function) }
    }

    private fun mark() = program.runTransaction("mark noreturn") {
        markNoReturn(program, program.memory.loadedAndInitializedAddressSet)
    }

    private fun external() = program.functionManager.externalFunctions.single { it.name == "assert" }

    private fun function(at: String): Function = program.functionManager.getFunctionAt(builder.addr(at))

    private companion object {
        const val STUB = "0x400000"
        const val CALLER = "0x400010"
    }
}
