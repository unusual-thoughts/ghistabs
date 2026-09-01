package ghistabs.build

import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.plugins.ExtraPropertiesExtension
import org.gradle.internal.extensions.core.extra
import java.util.*
import kotlin.io.path.Path
import kotlin.io.path.exists
import kotlin.io.path.inputStream

fun Project.envOrProp(key: String) = System.getenv(key)?.ifBlank { null }
    ?: findProperty(key)?.toString()?.ifBlank { null }

@Suppress("UNCHECKED_CAST")
fun <V> ExtraPropertiesExtension.getOrCreate(key: String, create: () -> V): V = when {
    has(key) -> get(key) as V
    else -> create().also { set(key, it) }
}

/** `GHIDRA_INSTALL_DIR`, else `-PGHIDRA_INSTALL_DIR`, else the usual place. */
val Project.ghidraInstallDir get() = Path(
    extra.getOrCreate("GHIDRA_INSTALL_DIR") {
        envOrProp("GHIDRA_INSTALL_DIR") ?: "/opt/ghidra"
    },
)

/**
 * A dotted Ghidra version, comparable so a compat boundary can name the release it actually moved in:
 * `SourceFileManager` at 11.3, `ProgramLoader` at 12.0, `checkValidReplacement` at 12.1.
 */
data class GhidraVersion(val maj: Int, val min: Int, val sub: Int) : Comparable<GhidraVersion> {
    override fun compareTo(other: GhidraVersion) =
        compareValuesBy(this, other, GhidraVersion::maj, GhidraVersion::min, GhidraVersion::sub)

    override fun toString() = "$maj.$min.$sub"

    companion object {
        /** Absent components are 0, so `"11.3"` means 11.3.0; a suffix (`12.1-DEV`) is ignored. */
        fun of(version: String) = version.split('.')
            .map { it.takeWhile(Char::isDigit).toIntOrNull() ?: 0 }
            .let { GhidraVersion(it.getOrElse(0) { 0 }, it.getOrElse(1) { 0 }, it.getOrElse(2) { 0 }) }
    }
}

/**
 * `GHIDRA_VERSION` (which `gradle.yml` already sets), else `-PGHIDRA_VERSION`, else the install's own
 * `application.version` — e.g. `12.1.2`. Read from the file rather than off the `ghidra_version` extra
 * `buildExtension.gradle` sets, so it is available before that script is applied.
 */
val Project.ghidraVersion: String get() = extra.getOrCreate("GHIDRA_VERSION") {
    envOrProp("GHIDRA_VERSION") ?: ghidraProperty("application.version")
}

/**
 * The Java level the install builds extensions at — `buildExtension.gradle` sets `sourceCompatibility`
 * from it, so Kotlin has to agree or Gradle rejects the build outright. 17 through 10.x, 21 from 11.
 */
val Project.ghidraJavaVersion: Int get() = ghidraProperty("application.java.compiler").toInt()

private val Project.ghidraPropertyFile get() = ghidraInstallDir.resolve("Ghidra/application.properties")

private val Project.ghidraProperties get() = Properties().apply { ghidraPropertyFile.inputStream().use(::load) }

/** One key out of the install's `Ghidra/application.properties`. */
private fun Project.ghidraProperty(key: String) = ghidraProperties.getProperty(key)
    ?: throw GradleException("no $key in $ghidraPropertyFile")

/** The install's version, typed. */
val Project.ghidra: GhidraVersion get() = GhidraVersion.of(ghidraVersion)

/** Whether the install is at least [version] — the form every compat boundary is written in. */
fun Project.ghidraAtLeast(version: String) = ghidra >= GhidraVersion.of(version)

/** Ghidra's user dir, named `<distroPrefix>_<releaseName>` e.g. `ghidra_12.1.2_DEV`. */
val Project.ghidraUserDir get() = Path(
    extra.getOrCreate("GHIDRA_USER_DIR") {
        envOrProp("GHIDRA_USER_DIR") ?: run {
            val distroPrefix = extra["DISTRO_PREFIX"].toString()
            val releaseName = extra["RELEASE_NAME"].toString()
            val dirName = "${distroPrefix}_$releaseName" // e.g. ghidra_12.0.4_DEV
            val home = System.getProperty("user.home")
            val modern = Path("$home/.config/ghidra/$dirName")
            val legacy = Path("$home/.ghidra/.$dirName")
            listOf(modern, legacy).firstOrNull { it.exists() }?.toString()
                ?: throw GradleException(
                    "No Ghidra user dir found at $modern or $legacy. Set GHIDRA_USER_DIR to override.",
                )
        }
    },
)
