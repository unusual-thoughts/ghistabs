import ghistabs.build.GhidraJavadoc
import ghistabs.build.ghidraInstallDir
import ghistabs.build.ghidraVersion
import kotlin.io.path.createDirectories
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

// Javadoc for all of the Ghidra install the build points at, not only the modules Ghidra's own
// createJavadocs takes in, marked where it goes past them: see GhidraJavadoc.

val javadocRoot = layout.buildDirectory.dir("ghidra-javadoc")
val sources = javadocRoot.map { it.dir("src") }
val modules = javadocRoot.map { it.file("modules.tsv") }
val resources = javadocRoot.map { it.dir("resources") }
val api = javadocRoot.map { it.dir("api") }

/** What javadoc needs beyond the install's jars: `generic.test`'s and `docking.test`'s JUnit 4. */
val ghidraJavadocClasspath: Configuration by configurations.creating {
    isCanBeConsumed = false
}

val ghidraJavadocSources = tasks.register("ghidraJavadocSources") {
    description = "Extract every *-src.zip of the Ghidra install, for ghidraJavadoc"
    val zips = GhidraJavadoc.sourceZips(ghidraInstallDir).keys.map { it.toFile() }
    inputs.files(zips)
    outputs.dirs(sources, resources)
    outputs.file(modules)
    doLast {
        val into = sources.get().asFile.toPath()
        project.delete(into)
        into.createDirectories()
        GhidraJavadoc.extract(ghidraInstallDir, into, modules.get().asFile.toPath())
        val res = resources.get().asFile.toPath().createDirectories()
        for (name in GhidraJavadoc.STYLESHEETS + GhidraJavadoc.SCRIPTS - GhidraJavadoc.PAGES_SCRIPT) {
            val bytes = GhidraJavadoc::class.java.getResourceAsStream("/ghidra-javadoc/$name")!!.use { it.readBytes() }
            res.resolve(name).writeBytes(bytes)
        }
        // Javadoc copies it as is; the real one is written once the pages exist.
        res.resolve(GhidraJavadoc.PAGES_SCRIPT).writeText("window.ghidraUnofficial = null;\n")
    }
}

val ghidraJavadoc = tasks.register<Javadoc>("ghidraJavadoc") {
    group = "documentation"
    description = "Javadoc for every module of the Ghidra install, those Ghidra's own leaves out marked"
    dependsOn(ghidraJavadocSources)
    source(sources.map { fileTree(it) { include("**/*.java") } })
    classpath = fileTree(ghidraInstallDir.resolve("Ghidra")) { include("**/*.jar") } + ghidraJavadocClasspath
    setDestinationDir(api.get().asFile)
    maxMemory = "6g"
    // One emulator class cites a {@snippet} file that only Ghidra's test sources have; every page is
    // still written.
    isFailOnError = false
    (options as StandardJavadocDocletOptions).apply {
        quiet()
        windowTitle = "Ghidra $ghidraVersion API (all modules)"
        docTitle = windowTitle
        addBooleanOption("Xdoclint:none", true)
        addMultilineStringsOption("-add-exports").value = GhidraJavadoc.ADD_EXPORTS
        val res = resources.get().asFile
        addMultilineStringsOption("-add-stylesheet").value = GhidraJavadoc.STYLESHEETS.map { res.resolve(it).path }
        addMultilineStringsOption("-add-script").value = GhidraJavadoc.SCRIPTS.map { res.resolve(it).path }
        tags =
            listOf(
                "apiNote:a:API Notes:",
                "implSpec:a:Implementation Requirements:",
                "implNote:a:Implementation Notes:",
            )
    }
    doLast {
        GhidraJavadoc.markUnofficial(
            api.get().asFile.toPath(),
            ghidraInstallDir.resolve("docs/GhidraAPI_javadoc.zip"),
            modules.get().asFile.toPath(),
        )
    }
}

tasks.register<Zip>("ghidraJavadocZip") {
    group = "documentation"
    description = "Zip ghidraJavadoc"
    from(ghidraJavadoc)
    into("ghidra_${ghidraVersion}_javadoc")
    archiveFileName.set("ghidra_${ghidraVersion}_javadoc.zip")
    destinationDirectory.set(javadocRoot)
}
