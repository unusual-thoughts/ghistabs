package ghicpp.hierarchy

import ghicpp.hierarchy.ClassHierarchy.ClassView
import ghicpp.hierarchy.ClassHierarchy.Origin
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** A base placed by hand takes the shape of the class it goes in: split around a vptr the class owns. */
@Tag("integration")
class PlaceBaseIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `a polymorphic base placed in a class owning its vfptr is split around it`() = withClasses(ownVfptr = true) {
            program,
            derived,
            base,
        ->
        program.overwrittenBy(derived, base, 0) mustBe emptyList()
        program.placeBase(derived, base, 0, false, 1) mustBe null

        val struct = program.dataTypeManager.getDataType(derived.structId!!) as Structure
        val vfptr = struct.getComponentAt(0)
        vfptr.fieldName mustBe ClassUtils.VFPTR
        (vfptr.dataType as Pointer).dataType.name mustBe "Derived_vftable"
        val fields = struct.getComponentAt(8)
        fields.fieldName mustBe "_base_"
        fields.dataType.name.startsWith("Base_fields") mustBe true
        struct.length mustBe 16
    }

    @Test
    fun `a base placed in a class with no vfptr of its own goes in whole`() = withClasses(ownVfptr = false) {
            program,
            derived,
            base,
        ->
        program.placeBase(derived, base, 0, false, 1) mustBe null

        val struct = program.dataTypeManager.getDataType(derived.structId!!) as Structure
        struct.getComponentAt(0).dataType.name mustBe "Base"
    }

    private fun withClasses(ownVfptr: Boolean, check: (Program, ClassView, ClassView) -> Unit) {
        val builder = ProgramBuilder("place", ProgramBuilder._X64)
        val program = builder.program
        try {
            builder.withTransaction {
                val dtm = program.dataTypeManager
                fun add(struct: Structure) = dtm.resolve(struct, DataTypeConflictHandler.DEFAULT_HANDLER) as Structure
                val cat = CategoryPath("/ClassDataTypes")
                val baseTable = add(StructureDataType(CategoryPath(cat, "Base"), "Base_vftable", 8))
                val derivedTable = add(StructureDataType(CategoryPath(cat, "Derived"), "Derived_vftable", 8))
                val base = add(
                    StructureDataType(CategoryPath(cat, "Base"), "Base", 0).apply {
                        add(PointerDataType(baseTable, 8), ClassUtils.VFPTR, null)
                        add(IntegerDataType.dataType, "a", null)
                        add(IntegerDataType.dataType, "b", null)
                    },
                )
                val derived = add(
                    StructureDataType(CategoryPath(cat, "Derived"), "Derived", 0).apply {
                        if (ownVfptr) {
                            add(
                                PointerDataType(derivedTable, 8),
                                ClassUtils.VFPTR,
                                null,
                            )
                        } else {
                            add(PointerDataType(null, 8), "p", null)
                        }
                    },
                )
                check(program, view(1, "Derived", dtm.getID(derived)), view(2, "Base", dtm.getID(base)))
            }
        } finally {
            builder.dispose()
        }
    }

    private fun view(id: Long, name: String, structId: Long) =
        ClassView(id, listOf(name), Origin.EDITED, null, null, null, structId, name, false, emptyList(), emptyList())
}
