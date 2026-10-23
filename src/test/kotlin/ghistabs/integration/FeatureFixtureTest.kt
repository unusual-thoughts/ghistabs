package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportOptions
import ghistabs.loadProgram
import ghistabs.test.defaultContext
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File

/** A test over the small programs in `features/`: [load] imports one, and it is closed after each test. */
abstract class FeatureFixtureTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    protected lateinit var artifacts: ImportArtifacts
    protected val program get() = loaded.program

    protected fun load(fixture: String, options: ImportOptions.() -> Unit = {}) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File(FEATURES, fixture))
        val ctx = program.defaultContext().apply { this.options.options() }
        artifacts = checkNotNull(ctx.import().artifacts) { "$fixture carries no stabs" }
    }

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    companion object {
        val FEATURES = File("src/test/resources/binaries/features")
    }
}
