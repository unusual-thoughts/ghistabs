package ghistabs.harvest

import ghistabs.diagnose.DummySink
import ghistabs.parse.SourceFile
import ghistabs.test.dummyHarvester
import ghistabs.test.mustBeSameAs
import ghistabs.test.mustNotBe
import ghistabs.test.mustNotBeNull
import org.junit.jupiter.api.Test

/**
 * Header-include edge cases in [Harvester]. Pure unit tests: [ghidra.util.task.TaskMonitor.DUMMY],
 * [DummySink] and constructed data only — no Program/DataTypeManager.
 */
class HarvesterGapTest {
    /**
     * A forward EXCL registers its placeholder in the shared registry, so a later BINCL for the
     * same (filename, checksum) reuses that instance instead of forking a divergent HeaderFile
     * (which would collide on content hash).
     */
    @Test
    fun `forward EXCL placeholder is shared with later BINCL`() {
        val registry = HeaderRegistry()
        val ctx1 = CuContext(SourceFile.CUSource("a.c"), sink = DummySink, registry = registry)
        val fn1 = ctx1.remount("hdr.h", 0x1234L)

        val ctx2 = CuContext(SourceFile.CUSource("b.c"), sink = DummySink, registry = registry)
        val fn2 = ctx2.beginInclude("hdr.h", 0x1234L)

        val h1 = ctx1.headerForFileNum(fn1)
        val h2 = ctx2.headerForFileNum(fn2)
        h1.mustNotBeNull("forward-EXCL should create a placeholder HeaderFile")
        h2.mustNotBeNull("BINCL should reuse the placeholder")
        h1.mustBeSameAs(h2, "placeholder and real BINCL must share one HeaderFile instance")
    }

    /** Collisions surface on [Harvest.rawCollisions] for post-hoc diagnostics; no production consumer reads it. */
    @Test
    fun `rawCollisions is accessible on an empty harvest`() {
        val harvest = dummyHarvester().second.harvest(emptyList())
        harvest.rawCollisions mustNotBe null
    }
}
