package ghistabs.materialize

import ghidra.framework.options.GProperties
import ghidra.util.Saveable
import ghidra.util.datastruct.DataTable
import ghidra.util.map.ObjectStorageAdapter
import ghistabs.cpp.Access
import ghistabs.cpp.ClassHierarchyRecords
import ghistabs.cpp.ClassHierarchyRecords.Base
import ghistabs.cpp.ClassHierarchyRecords.Entry
import ghistabs.cpp.MemberAttrs
import ghistabs.cpp.VirtKind
import ghistabs.test.*
import org.junit.jupiter.api.Test

class ClassHierarchyRecordTest {
    private fun <T : Saveable> T.roundTrip(fresh: T): T = fresh.also {
        val table = DataTable()
        save(ObjectStorageAdapter(table, 0))
        it.restore(ObjectStorageAdapter(table, 0))
    }

    /** Through the XML a custom program option is stored as. */
    private fun ClassHierarchyRecords.roundTrip(): ClassHierarchyRecords {
        val props = GProperties("test").also(::writeState)
        return ClassHierarchyRecords().also { it.readState(GProperties(props.saveToXml())) }
    }

    @Test
    fun `classes read back as saved, unresolved bases and template names included`() {
        val bases = listOf(
            Base(7, null, false, Access.PUBLIC),
            Base(9, null, true, Access.PROTECTED),
            Base(null, "std::iterator<std::input_iterator_tag, char, long>", true, Access.PRIVATE),
        )
        val classes = mapOf(12L to Entry(40, bases), 13L to Entry(null, emptyList()), 14L to Entry(41, bases.take(1)))
        ClassHierarchyRecords(classes).roundTrip().classes mustBe classes
        ClassHierarchyRecords(emptyMap()).roundTrip().classes mustBe emptyMap()
    }

    @Test
    fun `member attributes read back as saved`() {
        val attrs = MemberAttrs(Access.PROTECTED, VirtKind.VIRTUAL, isConst = true, isVolatile = false)
        attrs.roundTrip(MemberAttrs()) mustBe attrs
        // What a swept member can't know stays unknown.
        MemberAttrs(virt = VirtKind.VIRTUAL, isConst = true).let { it.roundTrip(MemberAttrs()) mustBe it }
    }
}
