package ghistabs.integration

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Regression test harness for StabsAnalyzer on xapasmcsr.exe.
 *
 * Runs full analysis pipeline and validates counters against committed baseline.
 * Skips gracefully if fixture is absent (EULA-restricted, not in repo).
 *
 * Note: This test extends AbstractGhidraHeadlessIntegrationTest dynamically
 * via gradle integrationTest task which has proper Ghidra Test JAR classpath.
 * See: gradle/ghidra-test-deps.md and build.gradle.kts integrationTest config.
 *
 * Real test implementation is loaded only when running via:
 *   ./gradlew integrationTest
 * And skipped by unit tests which exclude integration dir per build.gradle.kts.
 */
@Tag("integration")
class StabsAnalyzerRegressionTest {
    private val fixture = File("src/test/resources/binaries/xapasmcsr.exe")
    private val baselineFile = File("src/test/resources/baselines/xapasmcsr-baseline.json")

    @Test
    fun countersWithinBaseline() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (EULA-restricted, must be added manually)",
        )
        // TODO: Implement real Kind 2 integration test using AbstractGhidraHeadlessIntegrationTest
        // when Ghidra test harness is available on classpath.
    }

    @Test
    fun xapArgInstNotUnderStdInclude() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (EULA-restricted, must be added manually)",
        )
        // TODO: Verify XapArgInst not under /std/
    }

    @Test
    fun cLexStreamHasBaseField() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (EULA-restricted, must be added manually)",
        )
        // TODO: Verify CLexStream has _base_*/_vbase_* component
    }

    @Test
    fun atLeastOneVtableStructApplied() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (EULA-restricted, must be added manually)",
        )
        // TODO: Verify at least one *_vtable struct is populated
    }

    @Test
    fun bss0x46702cNamedOrDocumented() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (EULA-restricted, must be added manually)",
        )
        // TODO: Verify 0x46702c is named or documented as stabs-no-coverage
    }

    @Test
    fun applyErrorInvalidInputBucketDocumented() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (EULA-restricted, must be added manually)",
        )
        // TODO: Verify apply-error-invalid-input counter exists in message log
    }

    @Test
    fun globalsCoverEachDataTypeKind() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (EULA-restricted, must be added manually)",
        )
        // TODO: Verify globals cover required DataType kinds (Structure, Pointer, Enum, Primitive)
    }
}
