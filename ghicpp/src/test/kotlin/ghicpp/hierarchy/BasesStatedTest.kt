package ghicpp.hierarchy

import ghicpp.Access
import ghicpp.hierarchy.ClassHierarchy.*
import ghidra.program.model.symbol.SourceType
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class BasesStatedTest {
    private fun cls(origin: Origin, vararg sources: SourceType?) = ClassView(
        1, listOf("C"), origin, null, null, null, null, null, false, emptyList(),
        sources.map { BaseRef("B", 2, false, Access.PUBLIC, 0, it) }, null,
    )

    @Test
    fun `bases go by who stated each`() {
        cls(Origin.INFERRED, SourceType.IMPORTED, SourceType.USER_DEFINED).basesStated mustBe true
        cls(Origin.STABS, SourceType.IMPORTED, SourceType.ANALYSIS).basesStated mustBe false
        cls(Origin.STABS, null).basesStated mustBe false
    }

    @Test
    fun `no bases go by whether the origin says there are none`() {
        cls(Origin.STABS).basesStated mustBe true
        cls(Origin.EDITED).basesStated mustBe true
        cls(Origin.SWEPT).basesStated mustBe false
        cls(Origin.INFERRED).basesStated mustBe false
    }

    @Test
    fun `changing bases warns over imported ones, not a hand edit's`() {
        cls(Origin.EDITED, SourceType.IMPORTED).solidSource() mustBe "edited by hand"
        cls(Origin.EDITED).solidSource() mustBe null
        cls(Origin.STABS).solidSource() mustBe "stabs"
        cls(Origin.INFERRED, SourceType.ANALYSIS).solidSource() mustBe null
    }
}
