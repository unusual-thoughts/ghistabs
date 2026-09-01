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
import ghistabs.entrypoints.STRUCT_RETURN_ANALYZER_NAME
import ghistabs.entrypoints.StructReturnAnalyzer
import ghistabs.runTransaction
import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustBeEmpty
import ghistabs.test.mustNot
import org.junit.jupiter.api.AfterEach
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
        function(REG_RETURN).`return`.mustNot { isForcedIndirect }
        function(HIDDEN_RETURN).`return`.mustNot { isForcedIndirect }
        function(CDECL_POD).`return`.must("__cdecl force-indirects every struct") { isForcedIndirect }
        function(REG_RETURN).stackPurgeSize mustBe 0
        function(HIDDEN_RETURN).stackPurgeSize mustBe 4
        function(CDECL_POD).stackPurgeSize mustBe 0
    }

    @Test
    fun agreedRegisterReturnIsLeftAlone() {
        runAnalyzer()
        val f = function(REG_RETURN)
        f.callingConventionName.mustBe("__thiscall", "an 8-byte EDX:EAX return must keep the cspec convention")
        f.parameters.must("no hidden pointer should be injected") { none { it.name == RETURN_STORAGE_PTR } }
    }

    @Test
    fun purgingCalleeGetsHiddenPointer() {
        runAnalyzer()
        val f = function(HIDDEN_RETURN)
        f.callingConventionName mustBe "__thiscall_memret"
        f.`return`.must { isForcedIndirect }
        f.parameters.first().name mustBe RETURN_STORAGE_PTR
        f.parameters[1].name.mustBe("this", "hasthis must survive the rename")
        f.mustNot("storage should come from the convention, not be frozen") { hasCustomVariableStorage() }
    }

    /** The mirror direction — and the case the old custom-storage design could never reach. */
    @Test
    fun nonPurgingCalleeLosesHiddenPointer() {
        runAnalyzer()
        val f = function(CDECL_POD)
        f.callingConventionName mustBe "__cdecl_regret"
        f.`return`.mustNot("a bare RET means the POD really came back in EDX:EAX") { isForcedIndirect }
        f.parameters.must { none { it.name == RETURN_STORAGE_PTR } }
        f.parameters.must("hasthis must NOT leak into a __cdecl-derived model") { none { it.name == "this" } }
    }

    /** A program with nothing to correct must not be left carrying a spec extension it never used. */
    @Test
    fun conventionsAreNotInstalledWhenUnused() {
        program.runTransaction("drop the disagreeing functions") {
            listOf(HIDDEN_RETURN, CDECL_POD).forEach { program.functionManager.removeFunction(builder.addr(it)) }
        }
        runAnalyzer()
        SpecExtension.getCompilerSpecExtensions(program).mustBeEmpty()
    }

    /** Only the models actually used get installed — a memret-only program gains no regret model. */
    @Test
    fun onlyUsedConventionsAreInstalled() {
        program.runTransaction("drop the __cdecl function") {
            program.functionManager.removeFunction(builder.addr(CDECL_POD))
        }
        runAnalyzer()
        SpecExtension.getCompilerSpecExtensions(program).map { SpecExtension.getFormalName(it.first) } mustBe
            listOf("__thiscall_memret")
    }

    /** Re-running must not disturb already-corrected functions, in either direction. */
    @Test
    fun rerunIsIdempotent() {
        runAnalyzer()
        val before = signatures()
        runAnalyzer()
        signatures() mustBe before
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
