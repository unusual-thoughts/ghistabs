package ghistabs.build

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * [Fixtures.className] names files that are written to disk and then compiled, so a change here
 * silently orphans the task filters and the progress listener rather than failing anything.
 */
class FixturesTest {
    private val corpus = listOf("appquery.exe", "box2d_tests", "crypto_mi_test_gcc345.exe")

    @Test
    fun classNameMatchesTheGeneratedFiles() {
        assertEquals("AppqueryExeConcurrentTest", Fixtures.className("appquery.exe", "CONCURRENT"))
        assertEquals("Box2dTestsAfterTest", Fixtures.className("box2d_tests", "AFTER"))
        assertEquals("CryptoMiTestGcc345ExeAfterTest", Fixtures.className("crypto_mi_test_gcc345.exe", "AFTER"))
    }

    @Test
    fun noFiltersMeansTheWholeMatrix() {
        val f = Fixtures(corpus)
        assertFalse(f.isNarrowed)
        assertEquals(6, f.plannedTotal)
        assertEquals(6, f.labels.size)
    }

    @Test
    fun filtersNarrowBothAxesAndTolerateWhitespace() {
        val f = Fixtures(corpus, fixtureFilter = " box2d_tests , appquery.exe ", modeFilter = "after")
        assertTrue(f.isNarrowed)
        assertEquals(2, f.plannedTotal)
        assertEquals(
            listOf("ghistabs.fixtures.Box2dTestsAfterTest", "ghistabs.fixtures.AppqueryExeAfterTest"),
            f.selectedClasses,
        )
        // Labels stay whole-corpus: the listener has to recognise any suite the run happens to emit.
        assertEquals(6, f.labels.size)
    }

    @Test
    fun blankFiltersAreNotNarrowing() {
        val f = Fixtures(corpus, fixtureFilter = "", modeFilter = "  ,  ")
        assertFalse(f.isNarrowed)
        assertEquals(corpus, f.selectedBinaries)
        assertEquals(Fixtures.MODES, f.selectedModes)
    }
}
