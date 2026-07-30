package ghistabs

import java.util.stream.Stream

/**
 * Single source of truth for the fixture corpus and the `-Pfixture=<exact filename>[,<filename>…]`
 * (→ `-DfixtureFilter`) narrowing — a comma-separated list of exact filenames. Parameterised suites
 * draw their fixture list from here via `@MethodSource("ghistabs.integration.IntegrationFixtures#…")`,
 * so one flag narrows every suite at the source (no per-test `assumeTrue` skip that still pays a full
 * import). Binaries are hand-placed under `src/test/resources/binaries/`;
 * an absent one is skipped by the individual test, not here.
 */
object IntegrationFixtures {
    /** Where the hand-placed fixture binaries live (gitignored, bouniaf). */
    val DIR = java.io.File("src/test/resources/binaries")

    /**
     * Every binary in [DIR], sorted — the directory listing IS the corpus, so a fixture can never be
     * on disk yet silently untested (that drift hid `box2d` and `tinyxml2.cpp.o`; both now live in
     * `src/test/resources/fixtures.bak/`). One generated test class per name — see generateFixtureTests.
     */
    val ALL: List<String> get() = DIR.listFiles()?.filter { it.isFile }?.map { it.name }?.sorted().orEmpty()

    /** The `-Pfixture` filter as a set of exact filenames (comma-separated); empty means "all". */
    private fun wantedFixtures(): Set<String> = System.getProperty("fixtureFilter").orEmpty()
        .split(',').map { it.trim() }.filterTo(mutableSetOf()) { it.isNotEmpty() }

    /** [names] narrowed by `-Pfixture`; blank keeps all. Errors when the filter selects nothing here. */
    fun select(names: List<String>): List<String> {
        val wanted = wantedFixtures()
        if (wanted.isEmpty()) return names
        return names.filter { it in wanted }.ifEmpty { error("none of $wanted in this suite: $names") }
    }

    /** Whether [name] passes the `-Pfixture` filter — for suites that skip via `assumeTrue` per name. */
    fun accepts(name: String): Boolean = wantedFixtures().let { it.isEmpty() || name in it }

    @JvmStatic fun all(): Stream<String> = select(ALL).stream()
}
