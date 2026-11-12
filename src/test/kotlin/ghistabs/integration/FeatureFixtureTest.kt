package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.LoadedProgram
import ghidrakt.loadProgram
import ghidrakt.test.TestBinaries
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportOptions
import ghistabs.test.defaultContext
import ghistabs.test.importAndAnalyze
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
        loaded = loadProgram(feature(fixture))
        val ctx = program.defaultContext().apply { this.options.options() }
        artifacts = checkNotNull(ctx.importAndAnalyze().artifacts) { "$fixture carries no stabs" }
    }

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    companion object {
        val FEATURES = File("src/test/resources/binaries/features")

        /** [name] in [FEATURES], or in ghicpp's when it is a build of `hello.cc`. */
        fun feature(name: String) = TestBinaries.file("features/$name")

        /** The builds of `features/hello.cc` that carry stabs: all but the MSVC, the stripped and the no-RTTI ones. */
        fun stabsHellos() = TestBinaries.HELLOS.list().orEmpty()
            .filter { it.startsWith("hello_") && "_msvc" !in it && "_stripped" !in it && "_nortti" !in it }
            .sorted()
    }
}
