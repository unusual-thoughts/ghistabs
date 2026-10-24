package ghistabs.integration

import ghidra.app.cmd.function.FunctionPurgeAnalysisCmd
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.database.SpecExtension
import ghidra.program.model.data.DWordDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.UnionDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.entrypoints.Correction
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
 *  - [REG_RETURN]    `__thiscall`, 8-byte aggregate, bare `RET`. Modelled on `FileSystemImage::root`,
 *    which keying on `Composite` alone used to corrupt.
 *  - [HIDDEN_RETURN] `__thiscall`, 4-byte aggregate, `RET 0x4` — the callee popped a hidden pointer.
 *    Modelled on `FileSystemEntry::name` returning a 4-byte `std::string`.
 *  - [CDECL_POD]     `__cdecl`, 8-byte aggregate, bare `RET` — mingw returns a trivial POD in EDX:EAX
 *    against a model that force-indirects.
 *  - [UNION_RETURN]  `__thiscall`, 4-byte *union*, `RET 0x4`. The cspec rules name `struct`, so a
 *    union is register-placed in every release — which is the only thing still keeping the sret
 *    direction reachable from 12.2, where structs are all hidden-returned already.
 *
 * The sizes are deliberately the wrong way round — the *bigger* aggregate is the register return — so
 * nothing here can pass by keying on size.
 *
 * **Which way each one disagrees is the cspec's business, and it has changed.** GP-5183 gave `__cdecl`
 * a `<datatype name="struct"/><hidden_return/>` rule; 47c7b910 ("All models return structures via
 * input pointer", in the 12.2 cycle) gave it to every model, so `__thiscall` flipped from EDX:EAX to
 * sret and [REG_RETURN] went from the agreeing fixture to a disagreeing one. Nothing below may name a
 * model or a direction it did not read off this program first: [agreesWithEpilogue] asks the cspec,
 * the purge answers for the epilogue, and the analyzer's job is to make the two meet.
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
                    setReturnType(returnTypeFor(at, size), SourceType.IMPORTED)
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

    /** The premise: the cspec places both `__thiscall` returns the same way, Ghidra's purge pass doesn't. */
    @Test
    fun onlyPurgeSeparatesTheAbis() {
        function(REG_RETURN).`return`.isForcedIndirect
            .mustBe(function(HIDDEN_RETURN).`return`.isForcedIndirect, "the cspec cannot tell these apart")
        function(REG_RETURN).stackPurgeSize mustBe 0
        function(HIDDEN_RETURN).stackPurgeSize mustBe 4
        function(CDECL_POD).stackPurgeSize mustBe 0
        FIXTURES.keys.partition { function(it).agreesWithEpilogue }
            .must("the fixtures must exercise both directions") { first.isNotEmpty() && second.isNotEmpty() }
    }

    /** Whatever the cspec already gets right keeps its model — no extension, no rename. */
    @Test
    fun agreedReturnsAreLeftAlone() {
        val agreeing = FIXTURES.keys.filter { function(it).agreesWithEpilogue }
            .associateWith { function(it).callingConventionName }
        runAnalyzer()
        agreeing.forEach { (at, convention) ->
            function(at).callingConventionName.mustBe(convention, "$at agreed with the cspec already")
            function(at).mustNot("storage should come from the convention, not be frozen") {
                hasCustomVariableStorage()
            }
        }
    }

    /** The sret direction: a callee that popped the slot must end up taking the hidden pointer. */
    @Test
    fun purgingCalleeGetsHiddenPointer() {
        runAnalyzer()
        val f = function(HIDDEN_RETURN)
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
            FIXTURES.keys.filterNot { function(it).agreesWithEpilogue }
                .forEach { program.functionManager.removeFunction(builder.addr(it)) }
        }
        runAnalyzer()
        SpecExtension.getCompilerSpecExtensions(program).mustBeEmpty()
    }

    /** Only the models actually used get installed: the set is exactly the corrections that landed. */
    @Test
    fun onlyUsedConventionsAreInstalled() {
        val stock = program.compilerSpec.callingConventions.map { it.name }.toSet()
        runAnalyzer()
        val used = FIXTURES.keys.map { function(it).callingConventionName }.filterNot { it in stock }.distinct()
        used.mustNot("nothing was corrected, so this asserts nothing") { isEmpty() }
        SpecExtension.getCompilerSpecExtensions(program)
            .map { SpecExtension.getFormalName(it.first) }.sorted() mustBe used.sorted()
    }

    /** Both corrections must stay reachable — the union is what keeps sret alive from 12.2 on. */
    @Test
    fun bothDirectionsAreExercised() {
        runAnalyzer()
        val used = FIXTURES.keys.map { function(it).callingConventionName }
        used.must("expected an sret correction, got $used") { any { it.endsWith(Correction.TO_MEMORY.suffix) } }
        used.must("expected a register correction, got $used") { any { it.endsWith(Correction.TO_REGISTER.suffix) } }
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

    /** A union for [UNION_RETURN], a struct for the rest — see the class doc for why one is a union. */
    private fun returnTypeFor(at: String, size: Int) = if (at == UNION_RETURN) {
        UnionDataType("Uni$at").apply { add(DWordDataType.dataType, "word", null) }
    } else {
        StructureDataType("Agg$at", size)
    }

    /**
     * Does the cspec's placement already match the epilogue? `RET 0x4` is the callee popping a hidden
     * pointer — these fixtures purge nothing else — so a purge of 4 is sret and 0 is a register return.
     */
    private val Function.agreesWithEpilogue get() = `return`.isForcedIndirect == (stackPurgeSize == 4)

    private companion object {
        const val REG_RETURN = "0x400000"
        const val HIDDEN_RETURN = "0x400010"
        const val CDECL_POD = "0x400020"
        const val UNION_RETURN = "0x400030"
        const val RETURN_STORAGE_PTR = "__return_storage_ptr__"

        // mov eax,[esp+0x4] then either a bare RET (caller cleans) or RET 0x4 (callee pops the slot).
        val FIXTURES = mapOf(
            REG_RETURN to Triple("8b 44 24 04 c3", "__thiscall", 8),
            HIDDEN_RETURN to Triple("8b 44 24 04 c2 04 00", "__thiscall", 4),
            CDECL_POD to Triple("8b 44 24 04 c3", "__cdecl", 8),
            UNION_RETURN to Triple("8b 44 24 04 c2 04 00", "__thiscall", 4),
        )
    }
}
