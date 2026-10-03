package ghistabs.importer

import ghistabs.importer.ClassHierarchyRecord.Base
import ghistabs.parse.Access
import ghistabs.test.*
import org.junit.jupiter.api.Test

class ClassHierarchyRecordTest {
    @Test
    fun `a record reads back as written, unresolved bases and template names included`() {
        val record = mapOf(
            12L to listOf(Base(7, null, false, Access.PUBLIC), Base(9, null, true, Access.PROTECTED)),
            13L to listOf(Base(null, "std::iterator<std::input_iterator_tag, char, long>", false, Access.PRIVATE)),
            14L to emptyList(),
        )
        ClassHierarchyRecord.encode(record) mustBe
            "12\t+7\tv#9\n13\t-=std::iterator<std::input_iterator_tag, char, long>\n14"
        ClassHierarchyRecord.decode(ClassHierarchyRecord.encode(record)) mustBe record
    }

    @Test
    fun `a line or entry it can't read is skipped, not fatal`() {
        ClassHierarchyRecord.decode("x\t+1\n5\t?3\t+4\n\n") mustBe
            mapOf(5L to listOf(Base(4, null, false, Access.PUBLIC)))
    }
}
