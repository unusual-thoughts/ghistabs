package ghicpp

import ghicpp.ClassHierarchyRecords.Base
import ghicpp.ClassHierarchyRecords.Entry
import ghidra.framework.options.GProperties
import ghidra.program.model.symbol.SourceType
import ghidrakt.GPropertiesFormat
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class ClassRecordSourceTest {
    private fun roundTrip(record: ClassHierarchyRecords): ClassHierarchyRecords {
        val props = GProperties("record")
        GPropertiesFormat.encode(record, props)
        return GPropertiesFormat.decode<ClassHierarchyRecords>(props)
    }

    @Test
    fun `a recorded base keeps who stated it`() {
        val bases = listOf(
            Base(1, null, isVirtual = false, Access.PUBLIC, 0, SourceType.ANALYSIS),
            Base(2, null, isVirtual = true, Access.PROTECTED, null, SourceType.USER_DEFINED),
            Base(null, "Named", isVirtual = false, Access.PUBLIC, 8),
        )
        val record = ClassHierarchyRecords(mapOf(3L to Entry(4, bases)))
        roundTrip(record) mustBe record
    }

    @Test
    fun `a base recorded before its source was kept goes by the stabs' or RTTI's`() {
        val props = GProperties("record")
        val old = ClassHierarchyRecords(mapOf(3L to Entry(4, listOf(Base(1, null, false, Access.PUBLIC)))))
        GPropertiesFormat.encode(old, props)
        // As an older record has it: no source written.
        val base = props.getGProperties("classes").getGProperties("3").getGProperties("bases").getGProperties("0")
        base.remove("source")
        GPropertiesFormat.decode<ClassHierarchyRecords>(props).classes.getValue(3).bases.single().source mustBe
            SourceType.IMPORTED
    }
}
