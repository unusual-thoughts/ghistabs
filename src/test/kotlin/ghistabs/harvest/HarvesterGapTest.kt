package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DummySink
import ghistabs.importer.StabOnlyAddressResolver
import ghistabs.parse.SourceFile
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test

/**
 * Header-include edge cases in [Harvester]. Pure unit tests (Kind 1): TaskMonitor.DUMMY,
 * DummySink and constructed data only — no Program/DataTypeManager.
 */
class HarvesterGapTest {
    private fun createTestHarvester(): Harvester = Harvester(
        monitor = TaskMonitor.DUMMY,
        sink = DummySink,
        resolver = StabOnlyAddressResolver(),
    )

    /**
     * A forward EXCL registers its placeholder in the shared registry, so a later BINCL for the
     * same (filename, checksum) reuses that instance instead of forking a divergent HeaderFile
     * (which would collide on content hash).
     */
    @Test
    fun `forward EXCL placeholder is shared with later BINCL`() {
        val registry = HeaderRegistry()
        val ctx1 = IncludeContext(SourceFile.CUSource("a.c"), DummySink, registry)
        val fn1 = ctx1.remount("hdr.h", 0x1234L)

        val ctx2 = IncludeContext(SourceFile.CUSource("b.c"), DummySink, registry)
        val fn2 = ctx2.beginInclude("hdr.h", 0x1234L)

        val h1 = ctx1.headerForFileNum(fn1)
        val h2 = ctx2.headerForFileNum(fn2)
        assertNotNull(h1, "forward-EXCL should create a placeholder HeaderFile")
        assertNotNull(h2, "BINCL should reuse the placeholder")
        assertSame(h1, h2, "placeholder and real BINCL must share one HeaderFile instance")
    }

    /** Collisions surface on [Harvest.rawCollisions] for post-hoc diagnostics; no production consumer reads it. */
    @Test
    fun `rawCollisions is accessible on an empty harvest`() {
        val harvest = createTestHarvester().harvest(emptyList())
        assertNotNull(harvest.rawCollisions)
    }
}
