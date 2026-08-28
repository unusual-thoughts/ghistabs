import ghistabs.build.ghidraInstallDir
import ghistabs.build.ghidraUserDir
import java.util.zip.ZipFile
import kotlin.io.path.createDirectories

apply(from = ghidraInstallDir.resolve("support/buildExtension.gradle").toFile())

// buildExtension zips the whole projectDir, so whitelist the content instead
tasks.named<Zip>("buildExtension") {
    includeEmptyDirs = false
    include(
        "extension.properties",
        "Module.manifest",
        "README.md",
        "lib/**",
        "ghidra_scripts/**",
        "${project.name}.jar",
        "${project.name}-src.zip",
    )
}

/**
 * Unpack the extension zip into Ghidra's user extensions dir, replacing any previous install. Located
 * at execution: an absent user dir should fail this task, not every build.
 */
tasks.register("installExtension") {
    group = "ghidra"
    description = "Build and install the extension into the Ghidra user extensions directory"
    dependsOn("buildExtension")
    val projectName = project.name // not `name`: inside register{} that is the task's own name
    val extensionDir = ghidraUserDir.resolve("Extensions")
    val zip = (tasks.named("buildExtension").get() as Zip).archiveFile
    doLast {
        val targetDir = extensionDir.createDirectories().toFile()
        targetDir.resolve(projectName).takeIf { it.exists() }?.let {
            it.deleteRecursively()
            logger.lifecycle("Removed previous install: $it")
        }
        val archive = zip.get().asFile
        archive.unzipInto(targetDir)
        logger.lifecycle("Installed ${archive.name} → $targetDir")
        logger.lifecycle("Restart Ghidra to load the new build.")
    }
}

private fun File.unzipInto(target: File) = ZipFile(this).use { zf ->
    for (entry in zf.entries().asSequence()) {
        val out = File(target, entry.name)
        if (entry.isDirectory) {
            out.mkdirs()
        } else {
            out.parentFile.mkdirs()
            zf.getInputStream(entry).use { input -> out.outputStream().use(input::copyTo) }
        }
    }
}

/**
 * Populate `lib/` with the jars the extension ships, replacing buildExtension.gradle's copyDependencies
 * — a Copy, so dropped dependencies lingered and kept shipping, and its exclude spec is a Gradle 10
 * error. Filtered by path because that script's `api` holds the Ghidra install *and* lib/, and
 * `implementation` extends `api`: no configuration means "ours".
 */
tasks.register<Sync>("syncExtensionLibs") {
    group = "ghidra"
    description = "Populate lib/ with exactly the dependencies the extension ships"
    val libDir = layout.projectDirectory.dir("lib").asFile
    // Resolved here: a provider lambda closing over the Project can't be configuration-cached.
    val skip = listOf(ghidraInstallDir.toFile(), libDir).map { it.canonicalPath + File.separator }
    from(
        configurations.named("runtimeClasspath").map { cfg ->
            cfg.filter { jar -> skip.none { jar.canonicalPath.startsWith(it) } }
        },
    )
    into(libDir)
    preserve { include("README.txt") } // Ghidra's, not ours
}.also { sync ->
    tasks.named("copyDependencies") { enabled = false }
    tasks.named("compileKotlin") { dependsOn(sync) }
    tasks.named("buildExtension") { dependsOn(sync) }
}
