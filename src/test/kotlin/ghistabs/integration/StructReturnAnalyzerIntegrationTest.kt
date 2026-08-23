package ghistabs.integration

import ghidra.app.cmd.function.FunctionPurgeAnalysisCmd
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.database.SpecExtension
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.STRUCT_RETURN_ANALYZER_NAME
import ghistabs.StructReturnAnalyzer
import ghistabs.runTransaction
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Three functions covering the ways x86gcc.cspec and the epilogue can disagree, all with aggregate
 * returns the cspec is willing to place:
 *
 *  - [REG_RETURN]    `__thiscall`, 8-byte aggregate, bare `RET` — cspec agrees (EDX:EAX). Leave alone.
 *    Modelled on `FileSystemImage::root`, which keying on `Composite` alone used to corrupt.
 *  - [HIDDEN_RETURN] `__thiscall`, 4-byte aggregate, `RET 0x4` — cspec says EAX, epilogue says sret.
 *    Modelled on `FileSystemEntry::name` returning a 4-byte `std::string`.
 *  - [CDECL_POD]     `__cdecl`, 8-byte aggregate, bare `RET` — cspec force-indirects every struct
 *    (GP-5183), but mingw returns a trivial POD in EDX:EAX. The mirror case.
 *
 * The sizes are deliberately the wrong way round — the *bigger* aggregate is the register return — so
 * nothing here can pass by keying on size.
 */
@Tag("integration")
class StructReturnAnalyzerIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("structret", ProgramBuilder._X86, "gcc", this)
        builder.createMemory(".text", "0x400000", 0x100)
        FIXTURES.forEach { (at, spec) ->
            val (bytes, convention, size) = spec
            builder.setBytes(at, bytes, true)
            builder.createFunction(at)
            program.runTransaction("signature") {
                function(at).apply {
                    setCallingConvention(convention)
                    setReturnType(StructureDataType("Agg$at", size), SourceType.IMPORTED)
                }
            }
        }
        program.runTransaction("purge") {
            FunctionPurgeAnalysisCmd(program.memory.loadedAndInitializedAddressSet)
                .applyTo(program, TaskMonitor.DUMMY)
        }
        // ProgramBuilder's transactions trigger ambient auto-analysis, which runs this very analyzer
        // mid-fixture — and does so before every return type is set, so only some functions get it.
        // Rewind to the pre-analysis state so each test drives the analyzer explicitly.
        program.runTransaction("rewind ambient analysis") {
            FIXTURES.forEach { (at, spec) -> function(at).setCallingConvention(spec.second) }
            SpecExtension(program).run {
                SpecExtension.getCompilerSpecExtensions(program)
                    .forEach { removeCompilerSpecExtension(it.first, TaskMonitor.DUMMY) }
            }
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    /** The premise: the cspec cannot separate these, Ghidra's own purge pass can. */
    @Test
    fun onlyPurgeSeparatesTheAbis() {
        assertFalse(function(REG_RETURN).`return`.isForcedIndirect)
        assertFalse(function(HIDDEN_RETURN).`return`.isForcedIndirect)
        assertTrue(function(CDECL_POD).`return`.isForcedIndirect, "__cdecl force-indirects every struct")
        assertEquals(0, function(REG_RETURN).stackPurgeSize)
        assertEquals(4, function(HIDDEN_RETURN).stackPurgeSize)
        assertEquals(0, function(CDECL_POD).stackPurgeSize)
    }

    @Test
    fun agreedRegisterReturnIsLeftAlone() {
        runAnalyzer()
        val f = function(REG_RETURN)
        assertEquals("__thiscall", f.callingConventionName, "an 8-byte EDX:EAX return must keep the cspec convention")
        assertTrue(f.parameters.none { it.name == RETURN_STORAGE_PTR }, "no hidden pointer should be injected")
    }

    @Test
    fun purgingCalleeGetsHiddenPointer() {
        runAnalyzer()
        val f = function(HIDDEN_RETURN)
        assertEquals("__thiscall_memret", f.callingConventionName)
        assertTrue(f.`return`.isForcedIndirect)
        assertEquals(RETURN_STORAGE_PTR, f.parameters.first().name)
        assertEquals("this", f.parameters[1].name, "hasthis must survive the rename")
        assertFalse(f.hasCustomVariableStorage(), "storage should come from the convention, not be frozen")
    }

    /** The mirror direction — and the case the old custom-storage design could never reach. */
    @Test
    fun nonPurgingCalleeLosesHiddenPointer() {
        runAnalyzer()
        val f = function(CDECL_POD)
        assertEquals("__cdecl_regret", f.callingConventionName)
        assertFalse(f.`return`.isForcedIndirect, "a bare RET means the POD really came back in EDX:EAX")
        assertTrue(f.parameters.none { it.name == RETURN_STORAGE_PTR })
        assertTrue(f.parameters.none { it.name == "this" }, "hasthis must NOT leak into a __cdecl-derived model")
    }

    /** A program with nothing to correct must not be left carrying a spec extension it never used. */
    @Test
    fun conventionsAreNotInstalledWhenUnused() {
        program.runTransaction("drop the disagreeing functions") {
            listOf(HIDDEN_RETURN, CDECL_POD).forEach { program.functionManager.removeFunction(builder.addr(it)) }
        }
        runAnalyzer()
        assertTrue(SpecExtension.getCompilerSpecExtensions(program).isEmpty())
    }

    /** Only the models actually used get installed — a memret-only program gains no regret model. */
    @Test
    fun onlyUsedConventionsAreInstalled() {
        program.runTransaction("drop the __cdecl function") {
            program.functionManager.removeFunction(builder.addr(CDECL_POD))
        }
        runAnalyzer()
        assertEquals(
            listOf("__thiscall_memret"),
            SpecExtension.getCompilerSpecExtensions(program).map { SpecExtension.getFormalName(it.first) },
        )
    }

    /** Re-running must not disturb already-corrected functions, in either direction. */
    @Test
    fun rerunIsIdempotent() {
        runAnalyzer()
        val before = signatures()
        runAnalyzer()
        assertEquals(before, signatures())
    }

    private fun signatures() = FIXTURES.keys.associateWith { at ->
        function(at).run { "$callingConventionName ${parameters.joinToString { "${it.name}:${it.variableStorage}" }}" }
    }

    private fun runAnalyzer() = program.runTransaction(STRUCT_RETURN_ANALYZER_NAME) {
        StructReturnAnalyzer()
            .added(program, program.memory.loadedAndInitializedAddressSet, TaskMonitor.DUMMY, MessageLog())
    }

    private fun function(at: String): Function = program.functionManager.getFunctionAt(builder.addr(at))

    private companion object {
        const val REG_RETURN = "0x400000"
        const val HIDDEN_RETURN = "0x400010"
        const val CDECL_POD = "0x400020"
        const val RETURN_STORAGE_PTR = "__return_storage_ptr__"

        // mov eax,[esp+0x4] then either a bare RET (caller cleans) or RET 0x4 (callee pops the slot).
        val FIXTURES = mapOf(
            REG_RETURN to Triple("8b 44 24 04 c3", "__thiscall", 8),
            HIDDEN_RETURN to Triple("8b 44 24 04 c2 04 00", "__thiscall", 4),
            CDECL_POD to Triple("8b 44 24 04 c3", "__cdecl", 8),
        )
    }
}
