package ghicpp.stl

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StandAloneDataTypeManager
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
        val dtm = StandAloneDataTypeManager("std")
        dtm.withTransaction<Exception>("lay") {
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
    }
}
