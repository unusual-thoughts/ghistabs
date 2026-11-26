package ghicpp

import ghicpp.hierarchy.moveIntoClass
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.*
import ghidrakt.test.mustBe
import ghidrakt.test.mustBeTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [moveIntoClass], as the decompiler's "Move Function into Class" runs it: the function lands in the class,
 * made where there is none, and becomes a method taking that class's `this`, whatever its signature's source.
 */
@Tag("integration")
class MoveIntoClassIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private val builders = mutableListOf<ProgramBuilder>()

    @AfterEach
    fun tearDown() = builders.forEach(ProgramBuilder::dispose)

    private fun builder(language: String, compiler: String) =
        ProgramBuilder("move", language, compiler, this).apply { createMemory(".text", "0x401000", 0x100) }
            .also(builders::add)

    /** A global function at [at] under [convention] with pointer-sized [params], its signature from [source]. */
    private fun ProgramBuilder.function(
        at: String,
        convention: String,
        params: List<DataType>,
        source: SourceType = SourceType.USER_DEFINED,
    ): Function = createEmptyFunction(null, at, 1, DataType.DEFAULT).also { f ->
        withTransaction {
            f.updateFunction(
                convention,
                ReturnParameterImpl(IntegerDataType.dataType, program),
                params.mapIndexed { i, t -> ParameterImpl("param_${i + 1}", t, program, SourceType.USER_DEFINED) },
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true,
                source,
            )
        }
    }

    private fun Function.moveTo(path: String) = program.runTransaction { program.moveIntoClass(this, path) }

    private val Function.storage get() = parameters.map { "${it.name}@${it.variableStorage}" }

    private val Function.thisType get() = parameters.first().dataType.displayName

    @Test
    fun `an MSVC __stdcall a user typed becomes a __thiscall with this in ECX, its stack arguments kept`() {
        val b = builder(ProgramBuilder._X86, "windows")
        val f = b.function("0x401000", "__stdcall", listOf(IntegerDataType()))
        val before = f.storage
        f.moveTo("Klass").name mustBe "Klass"
        f.parentNamespace.name mustBe "Klass"
        f.callingConventionName mustBe "__thiscall"
        f.storage mustBe listOf("this@ECX:4 (auto)") + before
        f.thisType mustBe "Klass *"
    }

    @Test
    fun `a gcc x86 __cdecl's first argument becomes this, and a nested class is made where there is none`() {
        val b = builder(ProgramBuilder._X86, "gcc")
        val f = b.function("0x401000", "__cdecl", listOf(PointerDataType(b.program.dataTypeManager), IntegerDataType()))
        val cls = f.moveTo("outer::Inner")
        cls.getName(true) mustBe "outer::Inner"
        (f.parentNamespace is GhidraClass).mustBeTrue()
        f.callingConventionName mustBe "__thiscall"
        f.storage mustBe listOf("this@Stack[0x4]:4 (auto)", "param_2@Stack[0x8]:4")
        f.thisType mustBe "Inner *"
    }

    @Test
    fun `a namespace already so named is made a class, and moving again changes nothing`() {
        val b = builder(ProgramBuilder._X86, "windows")
        b.program.runTransaction {
            b.program.symbolTable.createNameSpace(null, "Plain", SourceType.USER_DEFINED)
        }
        val f = b.function("0x401000", "__stdcall", emptyList())
        f.moveTo("Plain")
        (f.parentNamespace is GhidraClass).mustBeTrue()
        val after = f.storage
        f.moveTo("Plain")
        f.storage mustBe after
    }

    @Test
    fun `where no convention takes this, the first parameter becomes this, typed with the class`() {
        val b = builder(ProgramBuilder._X64, "gcc")
        val f = b.function(
            "0x401000",
            Function.DEFAULT_CALLING_CONVENTION_STRING,
            listOf(PointerDataType(b.program.dataTypeManager)),
        )
        f.moveTo("Klass")
        f.parameters.map { it.name } mustBe listOf("this")
        f.thisType mustBe "Klass *"
    }
}
