package ghistabs.build

import java.io.File

/**
 * The fixture corpus: every binary under `src/test/resources/binaries`, crossed with the analyzer
 * modes. Gradle schedules whole classes onto forks, so one generated test class per binary × mode is
 * what parallelises — [className] is that naming, shared by the generator, the task filters and the
 * progress listener.
 *
 * [fixtureFilter] and [modeFilter] are the raw `-Pfixture=` / `-Pmode=` values; blank means everything.
 */
class Fixtures(val binaries: List<String>, fixtureFilter: String? = null, modeFilter: String? = null) {
    val modes = MODES

    val selectedBinaries = split(fixtureFilter) ?: binaries

    val selectedModes = split(modeFilter)?.map { it.uppercase() } ?: modes

    /** True when `-Pfixture`/`-Pmode` narrowed the matrix, so task filters are worth applying. */
    val isNarrowed get() = selectedBinaries != binaries || selectedModes != modes

    /** Generated class FQN -> `binary/MODE`, for every fixture on disk. */
    val labels = binaries.flatMap { b -> modes.map { m -> "$GENERATED_PACKAGE.${className(b, m)}" to "$b/$m" } }
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
        /** The corpus is whatever binaries are in [dir]; `.md` is the folder's own README. */
        fun scan(dir: File, fixtureFilter: String?, modeFilter: String?) = Fixtures(
            dir.listFiles()?.filter { it.isFile && it.extension != "md" }?.map { it.name }?.sorted().orEmpty(),
            fixtureFilter,
            modeFilter,
        )

        /** Mirrors `ghistabs.Mode`. */
        val MODES = listOf("CONCURRENT", "AFTER")

        const val GENERATED_PACKAGE = "ghistabs.fixtures"

        /** `crypto_mi_test.exe` + `AFTER` -> `CryptoMiTestExeAfterTest`. */
        fun className(binary: String, mode: String) = binary.split(Regex("[^A-Za-z0-9]+")).filter { it.isNotEmpty() }
            .joinToString("") { part -> part.replaceFirstChar { it.uppercase() } } +
            mode.lowercase().replaceFirstChar { it.uppercase() } + "Test"
    }
}
