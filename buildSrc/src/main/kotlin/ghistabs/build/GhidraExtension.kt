package ghistabs.build

import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.file.RegularFile
import org.gradle.api.plugins.ExtraPropertiesExtension
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Sync
import org.gradle.internal.extensions.core.extra
import org.gradle.kotlin.dsl.register
import java.io.File
import java.util.zip.ZipFile
import kotlin.io.path.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists

fun Project.envOrProp(key: String) = System.getenv(key)?.ifBlank { null }
    ?: findProperty(key)?.toString()?.ifBlank { null }

@Suppress("UNCHECKED_CAST")
fun <V> ExtraPropertiesExtension.getOrCreate(key: String, create: () -> V): V = when {
    has(key) -> get(key) as V
    else -> create().also { set(key, it) }
}

/** `GHIDRA_INSTALL_DIR`, else `-PGHIDRA_INSTALL_DIR`, else the usual place. */
val Project.ghidraInstallDir get() = extra.getOrCreate("GHIDRA_INSTALL_DIR") {
    Path(envOrProp("GHIDRA_INSTALL_DIR") ?: "/opt/ghidra")
}

/** Ghidra's user dir, named `<distroPrefix>_<releaseName>` e.g. `ghidra_12.1.2_DEV`. */
val Project.ghidraUserDir get() = extra.getOrCreate("GHIDRA_USER_DIR") {
    envOrProp("GHIDRA_USER_DIR")?.let { Path(it) } ?: run {
        val distroPrefix = extra["DISTRO_PREFIX"].toString()
        val releaseName = extra["RELEASE_NAME"].toString()
        val dirName = "${distroPrefix}_$releaseName" // e.g. ghidra_12.0.4_DEV
        val home = System.getProperty("user.home")
        val modern = Path("$home/.config/ghidra/$dirName")
        val legacy = Path("$home/.ghidra/.$dirName")
        listOf(modern, legacy).firstOrNull { it.exists() }
            ?: throw GradleException("No Ghidra user dir found at $modern or $legacy. Set GHIDRA_USER_DIR to override.")
    }
}

/**
 * Unpack the extension zip into Ghidra's user extensions dir, replacing any previous install. Located
 * at execution: an absent user dir should fail this task, not every build.
 */
fun Project.registerInstallExtension(zip: Provider<RegularFile>) = tasks.register("installExtension") {
    group = "ghidra"
    description = "Build and install the extension into the Ghidra user extensions directory"
    dependsOn("buildExtension")
    val projectName = name
    val extensionDir = ghidraUserDir.resolve("Extensions")
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
fun Project.registerExtensionLibs() = tasks.register<Sync>("syncExtensionLibs") {
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
