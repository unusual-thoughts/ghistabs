package ghistabs.build

import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.plugins.ExtraPropertiesExtension
import org.gradle.internal.extensions.core.extra
import kotlin.io.path.Path
import kotlin.io.path.exists

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
