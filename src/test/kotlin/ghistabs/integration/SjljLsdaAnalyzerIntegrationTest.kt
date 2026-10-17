package ghistabs.integration

import ghidra.app.plugin.exceptionhandlers.gcc.datatype.DwarfEncodingModeDataType
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.SignedLeb128DataType
import ghidra.program.model.data.UnsignedLeb128DataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.CommentType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.entrypoints.SjljLsdaAnalyzer
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [SjljLsdaAnalyzer] over hand-built MinGW prologues, each storing a personality and an LSDA into
 * its unwind context the way gcc's SJLJ code does, and one LSDA: a single `catch (Foo&)`.
 */
@Tag("integration")
class SjljLsdaAnalyzerIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    private val personality = 0x401800
    private val lsda = 0x402000
    private val zti = 0x403000

    private fun hex(v: Int) = "0x${v.toString(16)}"

    private fun addr(v: Int): Address = program.addressFactory.defaultAddressSpace.getAddress(v.toLong())

    private fun le(v: Int) = byteArrayOf(v.toByte(), (v shr 8).toByte(), (v shr 16).toByte(), (v shr 24).toByte())

    private fun code(vararg b: Int) = b.map { it.toByte() }.toByteArray()

    /** `push %ebp; mov %esp,%ebp; sub $0x40,%esp`, the two stores, `leave; ret`. */
    private fun prologue(personality: Int, lsda: Int) = code(0x55, 0x89, 0xe5, 0x83, 0xec, 0x40) +
        code(0xc7, 0x45, 0xd8) + le(personality) + code(0xc7, 0x45, 0xdc) + le(lsda) + code(0xc9, 0xc3)

    /** Two call sites, the second catching type 1, `Foo`'s typeinfo; one byte of padding before it. */
    private val catchFoo get() = code(0xff, 0x00, 0x0d, 0x01, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00) + le(zti)

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("sjlj", ProgramBuilder._X86, "gcc", this)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x2000), true)
        builder.createMemory(".rdata", hex(zti), 0x100)
        builder.createEmptyFunction("___gxx_personality_sj0", hex(personality), 1, VoidDataType.dataType)
        builder.setBytes(hex(lsda), catchFoo)
        builder.createLabel(hex(zti), "__ZTI3Foo")
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun function(at: Int, name: String, personality: Int = this.personality, lsda: Int = this.lsda) {
        val code = prologue(personality, lsda)
        builder.setBytes(hex(at), code)
        builder.createEmptyFunction(name, hex(at), code.size, VoidDataType.dataType)
    }

    private fun runAnalyzer() = program.runTransaction("sjlj") {
        SjljLsdaAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
    }

    private fun dataAt(offset: Int) = program.listing.getDefinedDataAt(addr(lsda + offset))

    @Test
    fun laysTheTablesAPrologueStores() {
        function(0x401000, "_ZN3Bar3runEv")
        SjljLsdaAnalyzer().must("a gcc x86 program must be analyzable") { canAnalyze(program) }
        runAnalyzer()

        dataAt(0)?.dataType.mustBeA<DwarfEncodingModeDataType>()
        dataAt(2)?.dataType.mustBeA<UnsignedLeb128DataType>()
        dataAt(4)?.dataType.mustBeA<UnsignedLeb128DataType>()
        dataAt(9)?.dataType.mustBeA<SignedLeb128DataType>()
        dataAt(11)?.dataType?.name.mustBe("Alignment")
        val type = dataAt(12)
        type?.dataType.mustBeA<Pointer>()
        type?.value.mustBe(addr(zti))
        program.listing.getComment(CommentType.EOL, addr(lsda + 9)).mustBe("(LSDA Action Table) Type Filter")

        val label = program.symbolTable.getSymbols(addr(lsda)).single { it.name == SjljLsdaAnalyzer.LABEL }
        label.parentNamespace.name.mustBe("_ZN3Bar3runEv")
        program.symbolTable.getPrimarySymbol(addr(lsda))?.name.mustBe("lsda_exception_table_00402000")
    }

    /** Two functions sharing one LSDA, as identical COMDAT copies can: laid once, labelled for each. */
    @Test
    fun labelsASharedTableForEachFunction() {
        function(0x401000, "first")
        function(0x401100, "second")
        runAnalyzer()
        program.symbolTable.getSymbols(addr(lsda)).filter { it.name == SjljLsdaAnalyzer.LABEL }
            .map { it.parentNamespace.name }.toSet().mustBe(setOf("first", "second"))
    }

    /**
     * A stripped binary names no personality: one stored before [SjljLsdaAnalyzer.MIN_UNNAMED] LSDAs
     * that all parse is taken as one, and fewer is not enough.
     */
    @Test
    fun findsAnUnnamedPersonalityByItsLsdas() {
        val unnamed = 0x401900
        val others = listOf(0x402100, 0x402200)
        others.forEach { builder.setBytes(hex(it), catchFoo) }

        function(0x401000, "first", unnamed)
        function(0x401100, "second", unnamed, others[0])
        runAnalyzer()
        dataAt(0).mustBeNull("laid an LSDA for an unnamed target only two stores make")

        function(0x401200, "third", unnamed, others[1])
        runAnalyzer()
        dataAt(0)?.dataType.mustBeA<DwarfEncodingModeDataType>()
    }

    /**
     * gcc schedules other prologue stores between the two, and a context below -128 puts the
     * personality's slot in a disp32 and the LSDA's, 4 above, back in a disp8.
     */
    @Test
    fun findsAStoreThePrologueSchedulesApart() {
        val scheduled = code(0x55, 0x89, 0xe5, 0x81, 0xec, 0xa0, 0x00, 0x00, 0x00) +
            code(0xc7, 0x85, 0x7c, 0xff, 0xff, 0xff) + le(personality) +
            code(0x89, 0x55, 0xac) +
            code(0xc7, 0x45, 0x80) + le(lsda) + code(0xc9, 0xc3)
        builder.setBytes("0x401000", scheduled)
        builder.createEmptyFunction("scheduled", "0x401000", scheduled.size, VoidDataType.dataType)
        runAnalyzer()
        dataAt(0)?.dataType.mustBeA<DwarfEncodingModeDataType>()
    }

    /**
     * A discarded COMDAT copy's LSDA stays in `.gcc_except_table`, packed after the kept ones: a
     * cleanup-only one, then two zero bytes aligning one with a type table.
     */
    @Test
    fun walksOnOverTablesNoFunctionStores() {
        function(0x401000, "kept")
        builder.setBytes(hex(lsda + 16), code(0xff, 0xff, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00) + catchFoo)
        runAnalyzer()
        dataAt(16)?.dataType.mustBeA<DwarfEncodingModeDataType>()
        dataAt(22)?.dataType?.name.mustBe("Alignment")
        dataAt(24)?.dataType.mustBeA<DwarfEncodingModeDataType>()
        program.symbolTable.getSymbols(addr(lsda + 24)).map { it.name }.mustBe(listOf("lsda_exception_table_00402018"))
        dataAt(40).mustBeNull("walked past the last table into zeros")
    }

    /** Bytes inside a function are code, whatever a store pair says: nothing is laid over them. */
    @Test
    fun leavesAFunctionBodyAlone() {
        function(0x401000, "caller")
        builder.createEmptyFunction("owner", hex(lsda - 4), 0x20, VoidDataType.dataType)
        runAnalyzer()
        dataAt(0).mustBeNull("laid an LSDA over a function body")
    }

    @Test
    fun leavesAWindowsProgramAlone() {
        val msvc = ProgramBuilder("msvc", ProgramBuilder._X86, "windows", this)
        try {
            SjljLsdaAnalyzer().mustNot("a windows program must not be analyzable") { canAnalyze(msvc.program) }
        } finally {
            msvc.dispose()
        }
    }
}
