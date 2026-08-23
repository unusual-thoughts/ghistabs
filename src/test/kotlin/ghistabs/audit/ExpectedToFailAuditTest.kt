package ghistabs.audit

import ghistabs.integration.Fixtures
import ghistabs.integration.StabsImportRegressionBase
import ghistabs.test.ExpectedToFail
import ghistabs.test.mustBeEmpty
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Every [ExpectedToFail] entry must correspond to a fixture that really does fail that test.
 *
 * The extension already reports an entry whose fixture starts *passing*. It cannot report the other way
 * an entry dies: the test acquiring an `assumeTrue` gate that skips on that fixture before it can fail.
 * A skip passes straight through, so the entry then sits in the list forever, documenting a defect that
 * is no longer being observed. That happened wholesale when the fixture-keyed assertions were rewritten
 * as corpus-wide ones with shape gates in front of them.
 *
 * Corpus-level, like [DemanglerWhitelistAuditTest], and for the same reason: an entry is dead only if
 * *no* fixture×mode invocation failed on it, which is not knowable until the whole run is in. Reads the
 * per-fork dumps [ghistabs.test.ExpectedToFailExtension] writes into `test-output/results/` and is run by the
 * `:auditWhitelist` task that `integrationTest` is finalizedBy.
 */
@Tag("audit")
class ExpectedToFailAuditTest {
    @Test
    fun everyEntryIsStillObserved() {
        val lines = File("build/test-output/results")
            .listFiles { f: File -> f.name.startsWith("expected-to-fail-") }.orEmpty()
            .flatMap { it.readLines() }
            .mapNotNull { it.split(' ').takeIf { p -> p.size == 3 } }

        // A partial run misrepresents the corpus: a fixture that was filtered out contributes no lines
        // and every entry naming it would read as dead. Require that each annotated method was reached
        // on every fixture on disk.
        val declared = StabsImportRegressionBase::class.java.declaredMethods
            .mapNotNull { m -> m.getAnnotation(ExpectedToFail::class.java)?.let { m.name to it.fixtures.toSet() } }
        assumeTrue(declared.isNotEmpty(), "no @ExpectedToFail entries to audit")
        val reached = lines.groupBy({ it[0] }, { it[1] }).mapValues { it.value.toSet() }
        val corpus = Fixtures.ALL.toSet()
        val short = declared.mapNotNull { (method, _) ->
            (corpus - reached[method].orEmpty()).takeIf { it.isNotEmpty() }?.let { "$method missing $it" }
        }
        assumeTrue(short.isEmpty(), "need a full-corpus run: $short")

        val failing = lines.filter { it[2] == "failed" }.groupBy({ it[0] }, { it[1] }).mapValues { it.value.toSet() }
        val dead = declared.flatMap { (method, fixtures) ->
            (fixtures - failing[method].orEmpty()).map { "$method: '$it' never failed — drop it" }
        }
        dead.sorted().mustBeEmpty("${dead.size} dead @ExpectedToFail entries: ${dead.joinToString("\n")}")
    }
}
