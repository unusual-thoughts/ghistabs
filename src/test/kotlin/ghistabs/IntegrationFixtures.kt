package ghistabs

import java.util.stream.Stream

/**
 * Single source of truth for the fixture corpus and the `-Pfixture=<exact filename>[,<filename>…]`
 * (→ `-DfixtureFilter`) narrowing — a comma-separated list of exact filenames. Parameterised suites
 * draw their fixture list from here via `@MethodSource("ghistabs.integration.IntegrationFixtures#…")`,
 * so one flag narrows every suite at the source (no per-test `assumeTrue` skip that still pays a full
 * import). Binaries are hand-placed under `src/test/resources/binaries/` (gitignored, EULA-restricted);
 * an absent one is skipped by the individual test, not here.
 */
object IntegrationFixtures {
    val CORE = listOf(
        "xapasmcsr.exe",
        "xmltest",
        "appquery.exe",
        "box2d_tests",
        "packfile.exe",
        "unpackfile.exe",
    )

    // gcc 4.2.1 / 3.4.5 stabs corpus (crypto / locale / xmltest), incl. PE-symbol-stripped variants.
    private val EXTENDED = listOf(
        "crypto_mi_test_gcc421.exe", "crypto_mi_test_gcc421_fullstabs.exe",
        "crypto_mi_test_gcc421_stripped.exe", "crypto_mi_test_gcc421_fullstabs_stripped.exe",
        "crypto_mi_test_gcc345.exe", "crypto_mi_test_gcc345_fullstabs.exe",
        "locale_test_customlibstdcxx.exe", "locale_test_customlibstdcxx_stripped.exe",
        "locale_test_gcc345_fullstabs.exe",
        "xmltest_gcc421.exe", "xmltest_gcc421_fullstabs.exe",
        "xmltest_gcc421_stripped.exe", "xmltest_gcc421_fullstabs_stripped.exe",
        "xmltest_gcc345.exe", "xmltest_gcc345_fullstabs.exe",
    )

    val ALL = CORE + EXTENDED

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

    @JvmStatic fun core(): Stream<String> = select(CORE).stream()

    @JvmStatic fun all(): Stream<String> = select(ALL).stream()

    @JvmStatic fun allWithBox2d(): Stream<String> = select(ALL + "box2d").stream()
}
