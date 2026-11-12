package ghistabs.materialize

import ghicpp.Access
import ghicpp.ClassHierarchyRecords
import ghicpp.ClassHierarchyRecords.Base
import ghicpp.ClassHierarchyRecords.Entry
import ghicpp.MemberAttrs
import ghicpp.VirtKind
import ghicpp.abi.StructorRole
import ghidra.framework.options.GProperties
import ghidra.program.model.symbol.SourceType
import ghidra.util.Saveable
import ghidra.util.datastruct.DataTable
import ghidra.util.map.ObjectStorageAdapter
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
        MemberAttrs(source = SourceType.ANALYSIS, structor = StructorRole.CONSTRUCTOR)
            .let { it.roundTrip(MemberAttrs()) mustBe it }
    }

    /** Version 1 attributes, with no source nor structor, as a program saved before them holds them. */
    private fun upgraded(access: Access?, virt: VirtKind?): MemberAttrs {
        val old = DataTable()
        ObjectStorageAdapter(old, 0).apply {
            putInt(access?.ordinal ?: -1)
            putInt(virt?.ordinal ?: -1)
            putBoolean(true)
            putBoolean(false)
        }
        val current = DataTable()
        MemberAttrs().upgrade(ObjectStorageAdapter(old, 0), 1, ObjectStorageAdapter(current, 0)) mustBe true
        return MemberAttrs().also { it.restore(ObjectStorageAdapter(current, 0)) }
    }

    @Test
    fun `version 1 attributes upgrade, from the stabs where they state an access`() {
        MemberAttrs().isUpgradeable(1) mustBe true
        upgraded(Access.PUBLIC, VirtKind.NORMAL) mustBe
            MemberAttrs(Access.PUBLIC, VirtKind.NORMAL, isConst = true, source = SourceType.IMPORTED)
        upgraded(null, VirtKind.VIRTUAL) mustBe MemberAttrs(virt = VirtKind.VIRTUAL, isConst = true)
    }
}
