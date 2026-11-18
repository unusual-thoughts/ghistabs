package ghicpp.gui

import ghicpp.dissect.FieldRetype
import ghicpp.hierarchy.SlotRenames
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class ActionResultsTest {
    @Test
    fun `Update Field Types lists each field typed, by class and offset, from what type to what`() {
        fieldTypesResult(
            listOf(
                "Shape" to emptyList(),
                "Circle" to listOf(
                    FieldRetype(0x10, "radius", "undefined8", "double"),
                    FieldRetype(0x8, "field_0x8", null, "int"),
                ),
            ),
            cancelled = false,
        ) mustBe """
            Typed 2 field(s):
              Circle +0x8 field_0x8: int
              Circle +0x10 radius: undefined8 → double
        """.trimIndent()
    }

    @Test
    fun `Update Field Types says when nothing changed, and when it was cancelled`() {
        fieldTypesResult(listOf("Shape" to emptyList()), cancelled = true) mustBe
            "No field changed type.\n\nCancelled: the fields typed before then keep their types."
    }

    @Test
    fun `a long list stops at forty lines and says how many more`() {
        val fields = (1..45).map { FieldRetype(it, "f$it", null, "int") }
        val lines = fieldTypesResult(listOf("A" to fields), cancelled = false).lines()
        lines.size mustBe 42
        lines.last() mustBe "  … and 5 more"
    }

    @Test
    fun `Apply Slot Names says how many it named and what kept its name`() {
        slotNamesResult(SlotRenames(0, 3, emptyList())) mustBe "Named 3 vftable slot(s)."
        slotNamesResult(SlotRenames(0, 0, listOf("Rect_vftable.area: taken"))) mustBe
            "No vftable slot was renamed.\n\nKept their old names:\n  Rect_vftable.area: taken"
    }

    @Test
    fun `Apply Signature says how many definitions each signature went into`() {
        signaturesResult(listOf("Rect::area" to 2, "Rect::perimeter" to 1)) mustBe """
            Applied 2 signature(s) to 3 vftable slot definition(s):
              Rect::area: 2 definition(s)
              Rect::perimeter: 1 definition(s)
        """.trimIndent()
    }
}
