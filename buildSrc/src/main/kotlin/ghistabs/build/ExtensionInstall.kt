package ghistabs.build

import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import java.io.File
import java.util.zip.ZipFile

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
