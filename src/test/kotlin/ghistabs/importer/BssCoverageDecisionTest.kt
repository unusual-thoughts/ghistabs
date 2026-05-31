package ghistabs.importer

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BssCoverageDecisionTest {
    @Test
    fun `classify returns NoCoverage for empty harvest`() {
        val range = AddrRange(0x1000L, 0x1010L)
        val harvest = emptyList<HarvestedAddr>()

        val result = BssCoverageDecision.classify(range, harvest)

        assertTrue(result is CoverageResult.NoCoverage)
        assertEquals(range, (result as CoverageResult.NoCoverage).range)
    }

    @Test
    fun `classify returns Covered for address inside range`() {
        val range = AddrRange(0x1000L, 0x1010L)
        val harvest =
            listOf(
                HarvestedAddr("var1", 0x1008L),
            )

        val result = BssCoverageDecision.classify(range, harvest)

        assertTrue(result is CoverageResult.Covered)
        val covered = result as CoverageResult.Covered
        assertEquals(range, covered.range)
        assertEquals(1, covered.coverers.size)
        assertEquals("var1", covered.coverers[0].symbolName)
    }

    @Test
    fun `classify returns NoCoverage for addresses outside range`() {
        val range = AddrRange(0x1000L, 0x1010L)
        val harvest =
            listOf(
                HarvestedAddr("var1", 0x0F00L),
                HarvestedAddr("var2", 0x2000L),
            )

        val result = BssCoverageDecision.classify(range, harvest)

        assertTrue(result is CoverageResult.NoCoverage)
    }

    @Test
    fun `classify filters to only in-range addresses`() {
        val range = AddrRange(0x1000L, 0x1010L)
        val harvest =
            listOf(
                HarvestedAddr("outside1", 0x0FFFL),
                HarvestedAddr("inside", 0x1005L),
                HarvestedAddr("outside2", 0x1011L),
            )

        val result = BssCoverageDecision.classify(range, harvest)

        assertTrue(result is CoverageResult.Covered)
        val covered = result as CoverageResult.Covered
        assertEquals(1, covered.coverers.size)
        assertEquals("inside", covered.coverers[0].symbolName)
    }

    @Test
    fun `classify ignores null resolved addresses`() {
        val range = AddrRange(0x1000L, 0x1010L)
        val harvest =
            listOf(
                HarvestedAddr("unresolved", null),
                HarvestedAddr("inside", 0x1005L),
            )

        val result = BssCoverageDecision.classify(range, harvest)

        assertTrue(result is CoverageResult.Covered)
        val covered = result as CoverageResult.Covered
        assertEquals(1, covered.coverers.size)
        assertEquals("inside", covered.coverers[0].symbolName)
    }
}
