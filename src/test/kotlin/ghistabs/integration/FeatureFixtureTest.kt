package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.importer.ImportArtifacts
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

    protected fun load(fixture: String) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File(FEATURES, fixture))
        artifacts = checkNotNull(program.defaultContext().import().artifacts) { "$fixture carries no stabs" }
    }

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    companion object {
        val FEATURES = File("src/test/resources/binaries/features")
    }
}
