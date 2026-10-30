package ghistabs.audit

import ghistabs.baseline.writeBaselines
import ghistabs.integration.OBSERVED_DIR
import ghistabs.integration.OUTPUT_ROOT
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Writes the shifted baselines, or with `-PregenerateBaselines=true` the committed ones, from the counts
 * every mode of integrationTest recorded ([writeBaselines]). Corpus-level, like [ExpectedToFailAuditTest]:
 * a baseline has to cover every mode, which is not knowable until the whole run is in.
 */
@Tag("audit")
class WriteBaselinesAuditTest {
    @Test
    fun writeBaselinesFromEveryMode() {
        assumeTrue(OBSERVED_DIR.isDirectory, "no counters recorded: integrationTest checked no baseline")
        writeBaselines(
            OBSERVED_DIR,
            File("src/test/resources/baselines"),
            File("$OUTPUT_ROOT/shifted-baselines"),
            regenerate = System.getProperty("regenerateBaselines") == "true",
        )
    }
}
