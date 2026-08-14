package ghistabs.build

import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Sync
import org.gradle.api.tasks.TaskProvider
import org.gradle.kotlin.dsl.register
import java.io.File
import java.util.zip.ZipFile
import kotlin.io.path.Path

/**
 * Where Ghidra is installed: `GHIDRA_INSTALL_DIR`, else `-PGHIDRA_INSTALL_DIR`, else the usual place.
 * Everything that has to know what an install looks like — the test-harness jars, the CLI launcher's
 * classpath, `lib/` filtering, and `support/buildExtension.gradle` itself — reads it from here.
 */
val Project.ghidraInstallDir get() = Path(
    System.getenv("GHIDRA_INSTALL_DIR")?.ifBlank { null }
        ?: findProperty("GHIDRA_INSTALL_DIR")?.toString()?.ifBlank { null }
        ?: "/opt/ghidra",
)

/**
 * Unpack the built extension zip into the Ghidra user extensions directory, replacing any previous
 * install. [distroPrefix] and [releaseName] are buildExtension.gradle's own ext properties, e.g.
 * `ghidra_12.1.2` + `DEV` — Ghidra's user dir is named after the pair, and `GHIDRA_USER_DIR` overrides
 * the search when it lives somewhere else entirely.
 */
fun Project.registerInstallExtension(zip: Provider<RegularFile>, distroPrefix: String, releaseName: String) =
    tasks.register("installExtension") {
        group = "ghidra"
        description = "Build and install the extension into the Ghidra user extensions directory"
        dependsOn("buildExtension")
        val projectName = name
        doLast {
            val targetDir = File(ghidraUserDir(distroPrefix, releaseName), "Extensions").apply { mkdirs() }
            File(targetDir, projectName).takeIf { it.exists() }?.let {
                it.deleteRecursively()
                logger.lifecycle("Removed previous install: $it")
            }
            zip.get().asFile.let { archive ->
                archive.unzipInto(targetDir)
                logger.lifecycle("Installed ${archive.name} → $targetDir")
            }
            logger.lifecycle("Restart Ghidra to load the new build.")
        }
    }

private fun ghidraUserDir(distroPrefix: String, releaseName: String): File {
    System.getenv("GHIDRA_USER_DIR")?.let { return File(it) }
    val dirName = "${distroPrefix}_$releaseName" // e.g. ghidra_12.0.4_DEV
    val home = System.getProperty("user.home")
    val modern = File("$home/.config/ghidra/$dirName")
    val legacy = File("$home/.ghidra/.$dirName")
    return listOf(modern, legacy).firstOrNull { it.exists() }
        ?: throw GradleException("No Ghidra user dir found at $modern or $legacy. Set GHIDRA_USER_DIR to override.")
}

private fun File.unzipInto(target: File) = ZipFile(this).use { zf ->
    zf.entries().asSequence().forEach { entry ->
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
 * Populate `lib/` with exactly the jars the extension ships, replacing buildExtension.gradle's
 * copyDependencies — a Copy, not a Sync, so a dropped dependency lingered there, and since that script
 * also puts the jars in lib/ back on the `api` configuration it kept itself on both classpaths and kept
 * shipping. Its exclude spec is a hard error in Gradle 10 (`Task.project` at execution time) too, and it
 * ordered only compileJava, so compileKotlin raced an emptied lib/.
 *
 * Filtering by path rather than by configuration is not an accident: that script's `api` holds both the
 * Ghidra install and lib/ itself, and `implementation` extends `api`, so no configuration means "ours".
 */
fun Project.registerExtensionLibs(): TaskProvider<Sync> {
    val sync = tasks.register<Sync>("syncExtensionLibs") {
        group = "ghidra"
        description = "Populate lib/ with exactly the dependencies the extension ships"
        val libDir = layout.projectDirectory.dir("lib").asFile
        // Prefixes rather than the enclosing script's vals — a provider lambda closing over those
        // captures the script object, which the configuration cache can't serialize.
        val skip = listOf(ghidraInstallDir.toFile(), libDir).map { it.canonicalPath + File.separator }
        from(
            configurations.named("runtimeClasspath").map { cfg ->
                cfg.filter { jar -> skip.none { jar.canonicalPath.startsWith(it) } }
            },
        )
        into(libDir)
        preserve { include("README.txt") } // Ghidra's, not ours
    }
    tasks.named("copyDependencies") { enabled = false }
    listOf("compileKotlin", "buildExtension").forEach { tasks.named(it) { dependsOn(sync) } }
    return sync
}
