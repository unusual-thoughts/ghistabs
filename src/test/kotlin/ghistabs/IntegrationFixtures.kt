package ghistabs

import org.junit.jupiter.api.Assumptions
import java.io.File
import java.util.stream.Stream

/**
 * Fixture corpus for the parameterized probe suites, narrowed by `-Pfixture=<filename>[,…]`
 * (→ `-DfixtureFilter`). The regression suite does not use this: it has one generated class per
 * fixture × mode, selected by gradle's test filter (see `:generateFixtureTests`). Binaries are
 * hand-placed under `src/test/resources/binaries/` (gitignored, EULA-restricted); an absent one is
 * skipped by the individual test.
 */
object IntegrationFixtures {
    private val dir = File("src/test/resources/binaries")

    /** The directory listing IS the corpus — a binary on disk can never sit silently untested.
     *  `.md` is the folder's own README, not a fixture. */
    val ALL: List<String> get() = dir.listFiles()
        ?.filter { it.isFile && it.extension != "md" }?.map { it.name }?.sorted().orEmpty()

    private val wanted: Set<String>
        get() = System.getProperty("fixtureFilter").orEmpty()
            .split(',').map { it.trim() }.filterTo(mutableSetOf()) { it.isNotEmpty() }

    /** Whether [name] passes `-Pfixture` — for suites that skip per name rather than at the source. */
    fun accepts(name: String) = wanted.let { it.isEmpty() || name in it }

    val acceptedFiles get() = ALL.filter(::accepts).map { File(dir, it) }

    /** The one fixture `-Pfixture` selected; skips the calling test unless it selected exactly one. */
    val singleFile: File get() = acceptedFiles.singleOrNull()
        ?: Assumptions.abort("set -Pfixture=<exact filename> to exactly one binary")

    /**
     * [name] by default, or whatever `-Pfixture` narrowed to when it named exactly one binary — for
     * a suite that needs *a* fixture of a given shape rather than the whole corpus. Skips the calling
     * test when neither exists, so a corpus missing the default still runs everything else.
     */
    fun orDefault(name: String): File = acceptedFiles.singleOrNull().takeIf { wanted.isNotEmpty() }
        ?: File(dir, name).takeIf { it.exists() && accepts(name) }
        ?: Assumptions.abort("$name absent and -Pfixture named no single replacement")

    /** [ALL] narrowed by `-Pfixture`; errors on a filter that matches nothing, so a typo fails loudly. */
    @JvmStatic
    fun all(): Stream<String> = ALL.filter(::accepts)
        .also { check(it.isNotEmpty() || wanted.isEmpty()) { "no fixture matches -Pfixture=$wanted" } }
        .stream()
}
