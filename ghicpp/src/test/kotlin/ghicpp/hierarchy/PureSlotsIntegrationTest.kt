package ghicpp.hierarchy

import ghicpp.Access
import ghicpp.ClassNaming
import ghicpp.abi.VftableBuilder
import ghicpp.abi.itanium.Itanium
import ghicpp.hierarchy.ClassHierarchy.BaseRef
import ghicpp.hierarchy.ClassHierarchy.ClassView
import ghicpp.hierarchy.ClassHierarchy.Origin
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.*
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.DtmRegistry
import ghidrakt.runTransaction
import ghidrakt.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Three Itanium classes, laid by hand: `A` declares the pure virtual `f`, `C` derives from `A` at offset 4 and
 * leaves `f` pure in its table for `A`, and `D` derives from `C` and overrides it, `int D::f()`. So two pure
 * slots, a primary table's and a secondary's, and one override for both, two tables down from `A`'s.
 */
@Tag("integration")
class PureSlotsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program
    private lateinit var hierarchy: ClassHierarchy

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("pure-slots", ProgramBuilder._X86, "gcc", this)
        builder.setExecute(builder.createMemory(".text", PURE, 0x200), true)
        builder.createMemory(".rodata", A_TABLE, 0x100)
        builder.createEmptyFunction("__cxa_pure_virtual", PURE, 1, VoidDataType.dataType)
        builder.createEmptyFunction("f", D_F, 1, IntegerDataType.dataType)
        for ((table, target) in listOf(A_TABLE to PURE, C_TABLE to PURE, D_TABLE to D_F)) {
            builder.setBytes(table, builder.addr(target).offset.toInt().le())
        }
        program.runTransaction {
            val (a, c, d) = listOf("A", "C", "D").map { classNamed(it) }
            program.functionManager.getFunctionAt(builder.addr(D_F)).apply {
                parentNamespace = d
                setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall)
                setSignatureSource(SourceType.IMPORTED)
            }
            layTable(a, A_TABLE, ClassNaming.VFTABLE, "A_vftable", PURE)
            layTable(c, C_TABLE, ClassNaming.vftableForLabel("A"), "C_vftable_for_A", PURE)
            layTable(d, D_TABLE, ClassNaming.vftableForLabel("A"), "D_vftable_for_A", D_F)
            hierarchy = ClassHierarchy(
                listOf(
                    view(a, emptyList()),
                    view(c, listOf(BaseRef("A", a.id, false, Access.PUBLIC, 4))),
                    view(d, listOf(BaseRef("C", c.id, false, Access.PUBLIC, 0))),
                ),
            )
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun `a pure slot is typed off an override, in a primary table and in a table for a base, this its own class`() {
        program.runTransaction { VirtualSlots(program, hierarchy).typePureSlots() } mustBe 2
        slot("A", "A_vftable") mustBe ("f" to "int __thiscall f(A * this)")
        slot("C", "C_vftable_for_A") mustBe ("f" to "int __thiscall f(C * this)")
        comment("C", "C_vftable_for_A") mustBe "pure virtual, typed off D::f"
    }

    @Test
    fun `typing the pure slots again changes nothing, and follows an override's signature once it changes`() {
        program.runTransaction { VirtualSlots(program, hierarchy).typePureSlots() }
        val types = program.dataTypeManager.getDataTypeCount(true)
        program.runTransaction { VirtualSlots(program, hierarchy).typePureSlots() } mustBe 0
        program.dataTypeManager.getDataTypeCount(true) mustBe types
        program.runTransaction {
            program.functionManager.getFunctionAt(builder.addr(D_F))
                .setReturnType(CharDataType.dataType, SourceType.USER_DEFINED)
        }
        // `char` itself, which the return type brings in.
        val withChar = program.dataTypeManager.getDataTypeCount(true)
        program.runTransaction { VirtualSlots(program, hierarchy).typePureSlots() } mustBe 2
        slot("A", "A_vftable") mustBe ("f" to "char __thiscall f(A * this)")
        program.dataTypeManager.getDataTypeCount(true) mustBe withChar
    }

    @Test
    fun `a pure slot typed otherwise stays as it is`() {
        program.runTransaction {
            val table = struct("A", "A_vftable")
            val def = FunctionDefinitionDataType(table.categoryPath, "declared", program.dataTypeManager).apply {
                setArguments(ParameterDefinitionImpl("this", PointerDataType(VoidDataType.dataType), null))
            }
            table.replace(0, PointerDataType(def, program.dataTypeManager), 4, "declared", null)
            VirtualSlots(program, hierarchy).typePureSlots() mustBe 1
        }
        slot("A", "A_vftable") mustBe ("declared" to "undefined declared(void * this)")
    }

    private fun classNamed(name: String): GhidraClass =
        program.symbolTable.createClass(program.globalNamespace, name, SourceType.IMPORTED).also { ns ->
            program.dataTypeManager.addDataType(
                StructureDataType(ClassNaming.vftableCategory(ns), name, 8),
                DataTypeConflictHandler.DEFAULT_HANDLER,
            )
        }

    private fun layTable(ns: GhidraClass, at: String, label: String, name: String, target: String) {
        val dtm = program.dataTypeManager
        val category = ClassNaming.vftableCategory(ns)
        val vftable = dtm.addDataType(StructureDataType(category, name, 0), null) as Structure
        VftableBuilder(DtmRegistry(dtm), program).addSlots(vftable, category, listOf(builder.addr(target)), Itanium)
        program.listing.createData(builder.addr(at), vftable)
        program.symbolTable.createLabel(builder.addr(at), label, ns, SourceType.IMPORTED)
    }

    private fun view(ns: GhidraClass, bases: List<BaseRef>) = ClassView(
        id = ns.id,
        path = listOf(ns.name),
        origin = Origin.INFERRED,
        vftable = null,
        vftableStructId = null,
        typeinfo = null,
        structId = null,
        structName = null,
        isAbstract = false,
        members = emptyList(),
        bases = bases,
    )

    private fun struct(cls: String, name: String) =
        program.dataTypeManager.getDataType(ClassNaming.vftableCategory(listOf(cls)), name) as Structure

    /** The first slot's field name and its definition's prototype, in [cls]'s table [name]. */
    private fun slot(cls: String, name: String): Pair<String?, String> {
        val field = struct(cls, name).getComponent(0)
        return field.fieldName to ((field.dataType as Pointer).dataType as FunctionDefinition).getPrototypeString(true)
    }

    private fun comment(cls: String, name: String) = struct(cls, name).getComponent(0).comment

    private fun Int.le() = byteArrayOf(toByte(), (this shr 8).toByte(), (this shr 16).toByte(), (this shr 24).toByte())

    private companion object {
        const val PURE = "0x401000"
        const val D_F = "0x401100"
        const val A_TABLE = "0x402000"
        const val C_TABLE = "0x402010"
        const val D_TABLE = "0x402020"
    }
}
