package ghistabs

import java.io.File
import java.util.stream.Stream

/**
 * Fixture corpus for the parameterised probe suites, narrowed by `-Pfixture=<filename>[,…]`
 * (→ `-DfixtureFilter`). The regression suite does not use this: it has one generated class per
 * fixture × mode, selected by gradle's test filter (see `:generateFixtureTests`). Binaries are
 * hand-placed under `src/test/resources/binaries/`; an absent one is
 * skipped by the individual test.
 */
object IntegrationFixtures {
    private val dir = File("src/test/resources/binaries")

    /** The directory listing IS the corpus — a binary on disk can never sit silently untested. */
    val ALL: List<String> get() = dir.listFiles()?.filter { it.isFile }?.map { it.name }?.sorted().orEmpty()

    private val wanted: Set<String>
        get() = System.getProperty("fixtureFilter").orEmpty()
            .split(',').map { it.trim() }.filterTo(mutableSetOf()) { it.isNotEmpty() }

    /** Whether [name] passes `-Pfixture` — for suites that skip per name rather than at the source. */
    fun accepts(name: String) = wanted.let { it.isEmpty() || name in it }

    /** [ALL] narrowed by `-Pfixture`; errors on a filter that matches nothing, so a typo fails loudly. */
    @JvmStatic
    fun all(): Stream<String> = ALL.filter(::accepts)
        .also { check(it.isNotEmpty() || wanted.isEmpty()) { "no fixture matches -Pfixture=$wanted" } }
        .stream()
}
