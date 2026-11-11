package ghicpp

import ghicpp.analyzers.MethodConventionAnalyzer
import ghicpp.recover.ClassPassTags
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.runTransaction
import ghistabs.test.mustBe
import ghistabs.test.mustBeFalse
import ghistabs.test.mustBeTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [fixMethodConvention] on what Ghidra makes of an MSVC x86 virtual function that never reads its `this`: a
 * `__stdcall`, its ECX set by every caller and read by none.
 */
@Tag("integration")
class MethodConventionIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private val builder = ProgramBuilder("msvc", ProgramBuilder._X86, "windows", this).apply {
        createMemory(".text", "0x401000", 0x100)
    }
    private val program = builder.program
    private val klass = program.runTransaction {
        program.symbolTable.createClass(null, "Klass", SourceType.ANALYSIS)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    /** A method of `Klass` at [at] under [convention] with [params], its signature from [source]. */
    private fun method(
        at: String,
        convention: String,
        params: List<DataType> = emptyList(),
        source: SourceType = SourceType.ANALYSIS,
    ): Function = builder.createEmptyFunction(null, at, 1, DataType.DEFAULT).also { f ->
        builder.withTransaction {
            f.parentNamespace = klass
            f.updateFunction(
                convention,
                ReturnParameterImpl(PointerDataType(program.dataTypeManager), program),
                params.mapIndexed { i, t -> ParameterImpl("param_${i + 1}", t, program, SourceType.ANALYSIS) },
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true,
                source,
            )
        }
    }

    private fun Function.fix(takesThis: Boolean = true) = program.runTransaction { fixMethodConvention(takesThis) }

    private val Function.storage get() = parameters.map { "${it.name}@${it.variableStorage}" }

    @Test
    fun `a __stdcall taking nothing becomes a __thiscall with this in ECX`() {
        val f = method("0x401000", "__stdcall")
        f.fix().mustBeTrue()
        f.callingConventionName mustBe "__thiscall"
        f.storage mustBe listOf("this@ECX:4 (auto)")
    }

    @Test
    fun `a __stdcall's stack arguments stay where they are after this`() {
        val f = method("0x401010", "__stdcall", listOf(PointerDataType(program.dataTypeManager), IntegerDataType()))
        val before = f.storage
        f.fix().mustBeTrue()
        f.callingConventionName mustBe "__thiscall"
        f.storage mustBe listOf("this@ECX:4 (auto)") + before
    }

    @Test
    fun `nor where it isn't known to take this, its signature isn't an analysis's, or it is __cdecl`() {
        method("0x401020", "__stdcall").fix(takesThis = false).mustBeFalse()
        method("0x401030", "__stdcall", source = SourceType.USER_DEFINED).fix().mustBeFalse()
        method("0x401040", "__cdecl").fix().mustBeFalse()
        method("0x401070", "__stdcall", source = SourceType.DEFAULT).fix().mustBeFalse()
    }

    @Test
    fun `the analyzer rerun makes one a class pass placed a __thiscall`() {
        val placed = method("0x401050", "__stdcall")
        val untagged = method("0x401060", "__stdcall")
        program.runTransaction {
            placed.addTag(ClassPassTags.METHOD)
            MethodConventionAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
        }
        placed.callingConventionName mustBe "__thiscall"
        untagged.callingConventionName mustBe "__stdcall"
    }
}
