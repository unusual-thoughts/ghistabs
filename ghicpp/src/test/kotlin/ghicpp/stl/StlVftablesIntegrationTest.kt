package ghicpp.stl

import ghicpp.Access
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.LongLongDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("integration")
class StlVftablesIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `a class with its own vfptr gets a vftable of its slots, overloads counted`() {
        val builder = ProgramBuilder("vftables", ProgramBuilder._X64)
        val dtm = builder.program.dataTypeManager
        try {
            builder.withTransaction {
                val std = CategoryPath("/std")
                val base = StructureDataType(std, "_Ref_count_base", 0, dtm).apply {
                    add(PointerDataType(null, 8, dtm), "{vfptr}", null)
                    add(IntegerDataType.dataType, "_Uses", null)
                }
                val plain = StructureDataType(std, "_Plain", 0, dtm).apply { add(IntegerDataType.dataType, "x", null) }
                dtm.resolve(base, DataTypeConflictHandler.DEFAULT_HANDLER)
                dtm.resolve(plain, DataTypeConflictHandler.DEFAULT_HANDLER)
                val destroy = FunctionDefinitionDataType("_func_void", dtm)
                val classes = listOf(
                    StdClass(
                        "/std/_Ref_count_base",
                        slots = listOf(StdSlot(0, "_Destroy"), StdSlot(16, "f"), StdSlot(8, "f")),
                    ),
                    StdClass("/std/_Plain", slots = listOf(StdSlot(0, "g"))),
                )
                val laid = StlVftables.lay(dtm, classes, 8) { _, slot -> destroy.takeIf { slot.offset == 0L } }

                laid mustBe 1
                val table = StlVftables.tableOf(
                    (dtm.getDataType("/std/_Ref_count_base") as Structure).getComponentAt(0).dataType,
                )!!
                table.pathName mustBe "/std/_Ref_count_base/_Ref_count_base_vftable"
                table.definedComponents.map { it.offset to it.fieldName } mustBe
                    listOf(0 to "_Destroy", 8 to "f", 16 to "f_1")
                ((table.getComponentAt(0).dataType as Pointer).dataType?.name) mustBe "_func_void"
                ((table.getComponentAt(8).dataType as Pointer).dataType) mustBe null
            }
        } finally {
            builder.dispose()
        }
    }

    @Test
    fun `a class adding virtuals to its base's vftable takes the vptr over, its table the base's and its own`() {
        val builder = ProgramBuilder("shape", ProgramBuilder._X64)
        val dtm = builder.program.dataTypeManager
        try {
            builder.withTransaction {
                val std = CategoryPath("/std")
                val base = StructureDataType(std, "error_category", 0, dtm).apply {
                    add(PointerDataType(null, 8, dtm), "{vfptr}", null)
                    add(LongLongDataType.dataType, "_Addr", null)
                }
                dtm.resolve(base, DataTypeConflictHandler.DEFAULT_HANDLER)
                val derived = StructureDataType(std, "_Generic_error_category", 0, dtm).apply {
                    add(dtm.getDataType("/std/error_category"), "", null)
                    add(IntegerDataType.dataType, "_Own", null)
                }
                dtm.resolve(derived, DataTypeConflictHandler.DEFAULT_HANDLER)
                val classes = listOf(
                    StdClass("/std/error_category", slots = listOf(StdSlot(0, "~error_category"), StdSlot(8, "name"))),
                    StdClass(
                        "/std/_Generic_error_category",
                        listOf(StdBase("/std/error_category", Access.PUBLIC, offset = 0)),
                        listOf(StdSlot(16, "extra")),
                    ),
                )
                val result = StlShape.apply(dtm, classes, 8) { _, _ -> null }

                result mustBe StlShape.Result(bases = 1, vftables = 1, split = 1)
                val struct = dtm.getDataType("/std/_Generic_error_category") as Structure
                struct.definedComponents.map { it.offset to it.fieldName } mustBe
                    listOf(0 to "vfptr", 8 to "_base_", 16 to "_Own")
                struct.getComponentAt(8).dataType.name mustBe "error_category_fields_8_16"
                val table = StlVftables.tableOf(struct.getComponentAt(0).dataType)!!
                table.pathName mustBe "/std/_Generic_error_category/_Generic_error_category_vftable"
                table.definedComponents.map { it.offset to it.fieldName } mustBe
                    listOf(0 to "~error_category", 8 to "name", 16 to "extra")
                // The base keeps its own vptr, renamed as ghicpp names it, pointing at its own table.
                val baseVfptr = (dtm.getDataType("/std/error_category") as Structure).getComponentAt(0)
                baseVfptr.fieldName mustBe "vfptr"
                StlVftables.tableOf(baseVfptr.dataType)!!.name mustBe "error_category_vftable"
            }
        } finally {
            builder.dispose()
        }
    }
}
