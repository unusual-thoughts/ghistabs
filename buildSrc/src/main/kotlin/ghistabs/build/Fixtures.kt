package ghistabs.build

import org.gradle.api.Project
import org.gradle.internal.extensions.core.extra
import java.io.File

/**
 * The fixture corpus crossed with the analyzer modes; [className] is the generated test class per pair,
 * shared by the generator, the task filters and the progress listener.
 *
 * [regressionFilter] is the raw `-Pregression[=<binary>[,…]]` value and selects the *suite*: present at
 * all means the run is the fixture matrix and nothing else. `-Pfixture` is a different axis and does
 * not appear here — it names the corpus the fixture-parameterised hand-written suites draw from
 * (`IntegrationFixtures`), and narrowing it must not deselect any class.
 *
 * [modeFilter] is `-Pmode=<MODE>[,…]`, `all` for every mode; [DEFAULT_MODES] when absent.
 */
class Fixtures(val binaries: List<String>, regressionFilter: String? = null, modeFilter: String? = null) {
    /** Whether `-Pregression` was given at all — the run is then the fixture matrix alone. */
    val regressionOnly = regressionFilter != null
    val selectedBinaries = split(regressionFilter) ?: binaries
    val selectedModes = split(modeFilter)
        ?.flatMap { if (it.equals(ALL_MODES, ignoreCase = true)) MODES else listOf(it.uppercase()) }
        ?.distinct()
        ?: DEFAULT_MODES

    /** Generated class FQN -> `binary/MODE`, for every fixture on disk. */
    val labels = binaries.flatMap { b -> MODES.map { m -> "$GENERATED_PACKAGE.${className(b, m)}" to "$b/$m" } }
        .toMap()

    /** FQNs of the selected subset — what a narrowed run should actually schedule. */
    val selectedClasses = selectedBinaries.flatMap { b ->
        selectedModes.map { m -> "$GENERATED_PACKAGE.${className(b, m)}" }
    }

    /** Generated classes for a mode this run does not want.
     *
     *  Excluded rather than de-selected, unlike [selectedClasses]: the mode axis has nothing to say
     *  about the hand-written integration classes, and a Gradle include-filter naming only generated
     *  classes drops every other class with them. `-Pmode` defaulting to [DEFAULT_MODES] would then
     *  silently take the whole behavioural suite out of every ordinary run. */
    val unselectedModeClasses get() = (MODES - selectedModes.toSet()).let { unwanted ->
        binaries.flatMap { b -> unwanted.map { m -> "$GENERATED_PACKAGE.${className(b, m)}" } }
    }

    /** How many generated classes a full run of the selection covers; at least one, for ETA maths. */
    val plannedTotal get() = (selectedBinaries.size * selectedModes.size).coerceAtLeast(1)

    private fun split(raw: String?) = raw.orEmpty()
        .split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { null }

    companion object {
        /** `.md` is the folder's own README, not a fixture. */
        fun scan(dir: File, regressionFilter: String?, modeFilter: String?) = Fixtures(
            dir.listFiles()?.filter { it.isFile && it.extension != "md" }?.map { it.name }?.sorted().orEmpty(),
            regressionFilter,
            modeFilter,
        )

        val Project.fixtures get() = extra.getOrCreate("fixtures") {
            scan(
                dir = layout.projectDirectory.dir("src/test/resources/binaries").asFile,
                regressionFilter = providers.gradleProperty("regression").orNull,
                modeFilter = providers.gradleProperty("mode").orNull,
            )
        }

        /** Mirrors `ghistabs.Mode`. */
        val MODES = listOf("CONCURRENT", "AFTER", "BEFORE")

        /** `AFTER` is the mode a GUI re-import actually takes and the one every assertion is written
         *  for, so it is what an ordinary run checks. The other two exist to catch ordering effects
         *  and cost 3x — `-Pmode=all` for CI, `-Pmode=BEFORE` for a fast loop on anything that does
         *  not read auto-analysis output. */
        val DEFAULT_MODES = listOf("AFTER")
        const val ALL_MODES = "all"
        const val GENERATED_PACKAGE = "ghistabs.fixtures"

        /** `crypto_mi_test.exe` + `AFTER` -> `CryptoMiTestExeAfterTest`. */
        fun className(binary: String, mode: String) = binary
            .split(Regex("[^A-Za-z0-9]+"))
            .filter { it.isNotEmpty() }
            .joinToString("") { part -> part.replaceFirstChar { it.uppercase() } } +
            mode.lowercase().replaceFirstChar { it.uppercase() } + "Test"
    }
}
