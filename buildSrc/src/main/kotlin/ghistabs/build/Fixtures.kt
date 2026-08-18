package ghistabs.build

import org.gradle.api.Project
import org.gradle.internal.extensions.core.extra
import java.io.File

/**
 * The fixture corpus crossed with the analyzer modes; [className] is the generated test class per pair,
 * shared by the generator, the task filters and the progress listener.
 *
 * [fixtureFilter] and [modeFilter] are the raw `-Pfixture=` / `-Pmode=` values; blank means everything.
 */
class Fixtures(val binaries: List<String>, fixtureFilter: String? = null, modeFilter: String? = null) {
    val selectedBinaries = split(fixtureFilter) ?: binaries
    val selectedModes = split(modeFilter)?.map { it.uppercase() } ?: MODES

    /** True when `-Pfixture`/`-Pmode` narrowed the matrix, so task filters are worth applying. */
    val isNarrowed get() = selectedBinaries != binaries || selectedModes != MODES

    /** Generated class FQN -> `binary/MODE`, for every fixture on disk. */
    val labels = binaries.flatMap { b -> MODES.map { m -> "$GENERATED_PACKAGE.${className(b, m)}" to "$b/$m" } }
        .toMap()

    /** FQNs of the selected subset — what a narrowed run should actually schedule. */
    val selectedClasses = selectedBinaries.flatMap { b ->
        selectedModes.map { m -> "$GENERATED_PACKAGE.${className(b, m)}" }
    }

    /** How many generated classes a full run of the selection covers; at least one, for ETA maths. */
    val plannedTotal get() = (selectedBinaries.size * selectedModes.size).coerceAtLeast(1)

    private fun split(raw: String?) = raw.orEmpty()
        .split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { null }

    companion object {
        /** `.md` is the folder's own README, not a fixture. */
        fun scan(dir: File, fixtureFilter: String?, modeFilter: String?) = Fixtures(
            dir.listFiles()?.filter { it.isFile && it.extension != "md" }?.map { it.name }?.sorted().orEmpty(),
            fixtureFilter,
            modeFilter,
        )

        val Project.fixtures get() = extra.getOrCreate("fixtures") {
            scan(
                dir = layout.projectDirectory.dir("src/test/resources/binaries").asFile,
                fixtureFilter = providers.gradleProperty("fixture").orNull,
                modeFilter = providers.gradleProperty("mode").orNull,
            )
        }

        /** Mirrors `ghistabs.Mode`. */
        val MODES = listOf("CONCURRENT", "AFTER", "BEFORE")
        const val GENERATED_PACKAGE = "ghistabs.fixtures"

        /** `crypto_mi_test.exe` + `AFTER` -> `CryptoMiTestExeAfterTest`. */
        fun className(binary: String, mode: String) = binary
            .split(Regex("[^A-Za-z0-9]+"))
            .filter { it.isNotEmpty() }
            .joinToString("") { part -> part.replaceFirstChar { it.uppercase() } } +
            mode.lowercase().replaceFirstChar { it.uppercase() } + "Test"
    }
}
