package ghicpp

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DWordDataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.runTransaction
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** [sizeClassStruct] grows a class struct, and the `<Class>_data` struct that ends it with it. */
@Tag("integration")
class ClassStructSizingIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program
    private lateinit var ns: GhidraClass

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("class-struct-sizing", ProgramBuilder._X86)
        program.runTransaction {
            ns = program.symbolTable.createClass(program.globalNamespace, "Foo", SourceType.USER_DEFINED)
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    /** A `Foo` of [length] bytes with the [fields] the class pass laid. */
    private fun foo(length: Int, fields: (StructureDataType) -> Unit) = program.runTransaction {
        val struct = StructureDataType(ClassNaming.vftableCategory(ns), ns.name, length, program.dataTypeManager)
        fields(struct)
        program.dataTypeManager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
    }

    private fun data(length: Int) = StructureDataType(ClassNaming.vftableCategory(ns), "Foo_data", length).apply {
        replaceAtOffset(0, DWordDataType.dataType, 4, "field_0x4", null)
    }

    @Test
    fun trailingDataGrowsWithTheClass() {
        foo(8) { it.replaceAtOffset(4, data(4), 4, "Foo_data", "own fields") }
        program.runTransaction { program.sizeClassStruct(ns, 16) }
        val struct = program.classStruct(ns)!!
        struct.length mustBe 16
        val data = struct.getComponentAt(4).dataType as Structure
        data.name mustBe "Foo_data"
        data.length mustBe 12
        data.getComponentAt(0).dataType.length mustBe 4
    }

    @Test
    fun dataBeforeAnotherFieldKeepsItsSize() {
        foo(12) {
            it.replaceAtOffset(0, data(4), 4, "Foo_data", "own fields")
            it.replaceAtOffset(8, DWordDataType.dataType, 4, "tail", null)
        }
        program.runTransaction { program.sizeClassStruct(ns, 16) }
        val struct = program.classStruct(ns)!!
        struct.length mustBe 16
        (struct.getComponentAt(0).dataType as Structure).length mustBe 4
    }
}
