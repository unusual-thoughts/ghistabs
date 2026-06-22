package ghistabs.parse

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DummySink
import ghistabs.harvest.Harvester
import ghistabs.harvest.HeaderRegistry
import ghistabs.harvest.IncludeContext
import ghistabs.importer.StabOnlyAddressResolver
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

/**
 * Unit tests for deviation table gaps identified in stabs-canonicalization.md §8.4.
 *
 * Verifies stabs-algo-audit.AC3.4: every untested case identified in the deviation table
 * is accounted for with active tests or @Disabled tests with justification.
 *
 * Tests are pure unit tests (Kind 1): no Program/DataTypeManager/Listing,
 * only TaskMonitor.DUMMY, DummySink, and constructed test data.
 *
 * Deviation Table Coverage:
 * - D1: Forward EXCL placeholder divergence (needs-fix) — active test
 * - D2: Attribution.categoryFor() incomplete (incomplete) — placeholder test
 * - D3: preSeedHeaders() forward-EXCL patching (incomplete) — placeholder test
 * - D4: walkDefinitions() anonymous naming (correct convention) — no test needed
 * - D5: rawByIdSnapshot vestigial (vestigial documentation) — no test needed
 * - D6: collidingAsts no production consumer (vestigial diagnostic-only) — active test
 * - D7: AttributionTraceDump incomplete (incomplete) — placeholder test
 */
class HarvesterGapTest {
    private fun createTestHarvester(): Harvester = Harvester(
        monitor = TaskMonitor.DUMMY,
        sink = DummySink,
        resolver = StabOnlyAddressResolver(),
    )

    /**
     * Test: Forward EXCL placeholder is stored globally so a later BINCL reuses it (D1 fixed).
     *
     * Source: stabs-canonicalization.md §6 deviation D1. `recall()` now registers the
     * placeholder in the shared `globalByFilenameChecksum` map; a subsequent
     * `getOrInsert()` for the same `(filename, checksum)` returns the same instance.
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
        assertNotNull(h1, "Forward-EXCL should create placeholder HeaderFile")
        assertNotNull(h2, "BINCL should reuse the placeholder")
        assertSame(h1, h2, "Placeholder and real BINCL must share one HeaderFile instance")
    }

    /**
     * Test: collidingAsts field exists and can be populated (D6).
     *
     * Deviation D6: collidingAsts map is populated during appendAsts() collision handling
     * but has no production consumer (diagnostic-only, per §9.6 audit).
     *
     * This test documents that the field exists, is part of the Harvest data class,
     * and can be used for post-hoc analysis, but production code does not read it.
     *
     * Source: stabs-canonicalization.md §6 deviation D6, §9.6 "collidingAsts consumer status".
     */
    @Test
    fun `collidingAsts field is present in Harvest`() {
        val harvester = createTestHarvester()
        val harvest = harvester.passA(emptyList())

        // Verify: collidingAsts field exists and is accessible
        assertNotNull(
            harvest.rawCollisions,
            "D6: collidingAsts field must exist in Harvest data class for collision recording",
        )
    }

    /**
     * D4: walkDefinitions() anonymous naming (correct convention).
     *
     * Anonymous inline TypeAst are named "${decl.id}" by convention, per Harvest.kt:401.
     * This is a design choice, not a spec-grounded requirement.
     * No test needed; the convention is implemented and not contested.
     */

    /**
     * D5: rawByIdSnapshot vestigial (comments in TypeRegistry.kt, ResolverDecision.kt).
     *
     * Field removed in commit 7d2bc56; vestigial comments remain.
     * This is an artifact of refactoring history, not a functional issue.
     * No test needed; this is a documentation-only deviation.
     */

    /**
     * D2: Attribution.categoryFor() HeaderSource handling (incomplete).
     *
     * Attribution.categoryFor() ignores HeaderSource as a distinct case;
     * header-attributed types fall through to multi-CU heuristic.
     *
     * This is a gap in the attribution layer that should be fixed to correctly
     * route header-attributed types to a "shared headers" category. For now,
     * we document that the function is called but the result may not reflect
     * the intended semantics.
     *
     * Source: stabs-canonicalization.md §6 deviation D2.
     */
    @Test
    @Disabled("D2 incomplete: Attribution.categoryFor() needs HeaderSource-aware routing")
    fun `attribution categoryFor ignores HeaderSource case`() {
        // TODO: When D2 is fixed, implement a test that verifies
        // header-attributed types receive a correct category (e.g., "shared headers")
        // distinct from single-CU or multi-CU categories.
    }

    /**
     * D3: preSeedHeaders() does not patch forward-EXCL placeholders.
     *
     * When a forward EXCL creates a placeholder and a later BINCL arrives,
     * preSeedHeaders() does not patch the placeholder to point to the real
     * HeaderFile. The divergence persists, leading to D1 (hash collisions).
     *
     * This is a design gap in preSeedHeaders() that should be addressed by
     * implementing a two-pass patch phase after pre-seeding completes.
     *
     * Source: stabs-canonicalization.md §6 deviation D3.
     */
    @Test
    @Disabled("D3 incomplete: preSeedHeaders() two-pass patching for forward EXCL")
    fun `preSeedHeaders should patch forward EXCL placeholders`() {
        // TODO: When D3 is fixed, implement a test that verifies
        // forward EXCL placeholders are replaced with real HeaderFile instances
        // when the BINCL arrives, preventing D1 divergence.
    }

    /**
     * D7: AttributionTraceDump diagnostic companion (incomplete).
     *
     * AttributionTraceDump is a diagnostic tool paired with categoryFor(),
     * but it has not been updated to handle the HeaderSource model.
     * This is a secondary diagnostic artifact and not critical for core function.
     *
     * Source: stabs-canonicalization.md §6 deviation D7.
     */
    @Test
    @Disabled("D7 incomplete: AttributionTraceDump not updated for HeaderSource")
    fun `attributionTraceDump not updated for HeaderSource model`() {
        // TODO: When D7 is fixed, verify that AttributionTraceDump
        // correctly logs decisions for header-attributed types.
    }

    /**
     * Deviation Table Self-Check:
     *
     * This test file documents all 7 deviations from the table:
     * - D1: Active test (broken behavior documented)
     * - D2: @Disabled with justification
     * - D3: @Disabled with justification
     * - D4: Comment (correct convention, no test needed)
     * - D5: Comment (documentation artifact, no test needed)
     * - D6: Active test (vestigial but populated)
     * - D7: @Disabled with justification
     *
     * Run: `grep -o "D[0-9]\+" src/test/kotlin/ghistabs/parser/HarvesterGapTest.kt | sort -u`
     * to verify all D-IDs are cited.
     */
}
