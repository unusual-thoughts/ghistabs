package ghistabs.integration

import ghidra.app.util.opinion.ElfLoader
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.CommentType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.applyDemangling
import ghistabs.diagnose.DummySink
import ghistabs.importer.StabsImporter
import ghistabs.materialize.cpp.VtableVirtualBases
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.runTransaction
import ghistabs.test.defaultContext
import ghistabs.test.must
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A class deriving from an undefined `basic_ifstream<char>`, in miniature: `Derived` derives from `Mid`,
 * which no CU defines, so its stab shows no virtual base. `Mid`'s typeinfo says it virtually inherits
 * `Wrap` through vtable offset −12, where `_ZTV7Derived` holds 16; `Wrap`, defined nowhere either, has
 * `Core` 4 bytes in (`basic_ios` keeps its vptr in front of `ios_base`), so `Core` goes at +20.
 */
@Tag("integration")
class VtableVirtualBaseIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".text", "0x400000", 1024)
        builder.createMemory(".data", "0x404000", 512)
        builder.createMemory(".stab", "0x402000", 4)
        builder.createMemory(".stabstr", "0x403000", 4)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun words(at: Long, vararg values: Long) = values.forEachIndexed { i, v ->
        val bytes = (0..3).joinToString(" ") { "%02x".format((v shr (8 * it)) and 0xff) }
        builder.setBytes("0x%x".format(at + 4 * i), bytes)
    }

    private fun label(at: Long, name: String) = builder.createLabel("0x%x".format(at), name)

    private fun layRtti(vbaseOffset: Long) {
        label(0x404010, "_ZTVN10__cxxabiv120__si_class_type_infoE")
        label(0x404020, "_ZTVN10__cxxabiv121__vmi_class_type_infoE")
        label(0x404040, "_ZTI4Core")
        label(0x404050, "_ZTI4Wrap")
        words(0x404050, 0x404028, 0, 0, 1, 0x404040, (4L shl 8) or 2)
        label(0x404070, "_ZTI3Mid")
        words(0x404070, 0x404028, 0, 0, 1, 0x404050, ((-12L shl 8) or 3) and 0xffffffffL)
        label(0x404090, "_ZTI7Derived")
        words(0x404090, 0x404018, 0, 0x404070)
        label(0x4040a0, "_ZTV7Derived")
        words(0x4040a0, vbaseOffset, 0, 0x404090, 0x400000)
        // Wrap's table in Derived's group: offset_to_top is minus where Wrap sits.
        words(0x4040b0, -vbaseOffset and 0xffffffffL, 0x404090, 0x400000)
    }

    private fun import(vararg derived: String): Pair<Structure, Map<String, List<String>>> {
        val stabs = listOf(
            "int:t(0,1)=r(0,1);-2147483648;2147483647;",
            "Core:T(0,4)=s8a:(0,1),0,32;b:(0,1),32,32;;",
            "Mid:t(0,2)=xsMid:",
        ) + derived
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "vbase.cpp")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val program = builder.program
        val ctx = program.defaultContext()
        StabsImporter(ctx).runOnRecords(StabReader.Result(records))
        val structs = program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>()
        return structs.single { it.name == "Derived" } to ctx.diagnostics.degradationTargets()
    }

    @Test
    fun aVirtualBaseTheStabCannotShowIsLaidWhereTheVtableSays() {
        layRtti(vbaseOffset = 16)
        val (derived, _) = import(DERIVED)

        val core = derived.getComponentAt(20)
        core.dataType.must("Core at +20") { name == "Core" && length == 8 }
        core.fieldName mustBe "_vbase_Core"
        core.comment.must("names the virtual base") { contains("virtual Wrap") && contains("+0x10") }
        derived.getComponentAt(8).fieldName mustBe "x"
        builder.program.listing.getComment(CommentType.EOL, builder.addr("0x4040a0")) mustBe "vbase offset: Wrap"
        derived.getComponentAt(16).must("Wrap's vptr in front of its Core") {
            fieldName == ClassUtils.VFPTR && offset == 16 && dataType is Pointer
        }
    }

    @Test
    fun aVirtualBaseOverOwnFieldsIsReportedNotLaid() {
        layRtti(vbaseOffset = 4)
        val (derived, degradations) = import(DERIVED)

        derived.getComponentAt(8).fieldName mustBe "x"
        degradations["vbase-layout-failed"].orEmpty().must("reported") { single().endsWith("Derived::Wrap") }
    }

    /** No stabs: the structs are whatever the program has, found by the class namespaces of its labels. */
    @Test
    fun withoutStabsTheClassStructsAreFoundByNamespace() {
        layRtti(vbaseOffset = 16)
        val program = builder.program
        val derived = program.runTransaction {
            // The GNU demangler only takes a program it recognizes as gcc's.
            program.executableFormat = ElfLoader.ELF_NAME
            for (sym in program.symbolTable.symbolIterator.iterator().asSequence().toList()) {
                if (sym.name.startsWith("_Z")) program.applyDemangling(sym.address, sym.name)
            }
            fun struct(name: String, size: Int, vararg ints: Pair<Int, String>) = program.dataTypeManager.addDataType(
                StructureDataType(CategoryPath.ROOT, name, size).apply {
                    ints.forEach { (at, field) -> replaceAtOffset(at, IntegerDataType.dataType, 4, field, null) }
                },
                DataTypeConflictHandler.DEFAULT_HANDLER,
            ) as Structure
            struct("Core", 8, 0 to "a", 4 to "b")
            struct("Derived", 32, 8 to "x").also { VtableVirtualBases(program, DummySink).layAll() mustBe 1 }
        }

        derived.getComponentAt(20).dataType.must("Core at +20") { name == "Core" }
    }

    private companion object {
        /** Polymorphic, as a class with a vtable is: one virtual, `f`, in slot 0. */
        const val DERIVED = "Derived:T(0,3)=s32!1,020,(0,2);x:(0,1),64,32;" +
            "f::(0,5)=#(0,3),(0,1),(0,6)=*(0,3);:_ZN7Derived1fEv;2A*0;(0,3);;;"
    }
}
