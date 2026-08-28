import ghistabs.build.Fixtures
import ghistabs.build.Fixtures.Companion.fixtures
import ghistabs.build.fixtureTestSource


/** One [fixtureTestSource] per binary × mode. */
tasks.register("generateFixtureTests") {
    description = "Generate one StabsImportRegressionBase subclass per fixture binary"
    val outDir = layout.buildDirectory.dir("generated/sources/fixtureTests/kotlin")
    // An input, so adding/removing a binary regenerates.
    inputs.property("fixtures", fixtures.binaries)
    outputs.dir(outDir)
    doLast {
        val pkgDir = outDir.get().asFile.resolve(Fixtures.GENERATED_PACKAGE.replace('.', '/'))
        pkgDir.deleteRecursively()
        pkgDir.mkdirs()
        val pairs = fixtures.binaries.flatMap { b -> Fixtures.MODES.map { m -> b to m } }
        pairs.forEach { (binary, mode) ->
            pkgDir.resolve("${Fixtures.className(binary, mode)}.kt").writeText(fixtureTestSource(binary, mode))
        }
        logger.lifecycle("generateFixtureTests: ${pairs.size} fixture classes")
    }
}
