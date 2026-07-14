package ghistabs

import java.util.stream.Stream

/**
 * Single source of truth for the fixture corpus and the `-Pfixture=<exact filename>`
 * (→ `-DfixtureFilter`) narrowing. Parameterised suites draw their fixture list from here via
 * `@MethodSource("ghistabs.integration.IntegrationFixtures#…")`, so one flag narrows every suite at
 * the source (no per-test `assumeTrue` skip that still pays a full import). Binaries are hand-placed
 * under `src/test/resources/binaries/`; an absent one is skipped by
 * the individual test, not here.
 */
object IntegrationFixtures {
    val CORE = listOf(
        "bouniafbouniaf.exe",
        "xmltest",
        "bouniaf.exe",
        "box2d_tests",
        "bouniaf.exe",
        "unbouniaf.exe",
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
    val SKELETON = listOf("bouniafbouniaf.exe", "xmltest", "bouniaf.exe", "box2d_tests")

    /** [names] narrowed by `-Pfixture`; blank filter keeps all. Errors on a filter that matches nothing. */
    fun select(names: List<String>): List<String> {
        val filter = System.getProperty("fixtureFilter").orEmpty()
        if (filter.isBlank()) return names
        return names.filter { it == filter }.ifEmpty { error("fixture '$filter' not in this suite: $names") }
    }

    @JvmStatic fun core(): Stream<String> = select(CORE).stream()

    @JvmStatic fun all(): Stream<String> = select(ALL).stream()

    @JvmStatic fun allWithBox2d(): Stream<String> = select(ALL + "box2d").stream()

    @JvmStatic fun skeleton(): Stream<String> = select(SKELETON).stream()
}
