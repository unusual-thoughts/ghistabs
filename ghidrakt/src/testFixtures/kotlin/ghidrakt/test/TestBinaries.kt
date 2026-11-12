package ghidrakt.test

import java.io.File

/**
 * Where the binary fixtures are, for every project's tests. Gradle passes each directory as a system
 * property; a test run from the project that holds it needs none.
 */
object TestBinaries {
    /** The corpus: the root project's `src/test/resources/binaries/`. */
    val DIR = dir("binariesDir", "src/test/resources/binaries")

    /** `hello.cc` and its builds: ghicpp's `src/test/resources/binaries/features/`. */
    val HELLOS = dir("hellosDir", "src/test/resources/binaries/features")

    /** [path] under [DIR], or a `features/hello…` build in [HELLOS]. */
    fun file(path: String): File =
        if (path.startsWith("features/hello")) File(HELLOS, path.removePrefix("features/")) else File(DIR, path)

    private fun dir(property: String, default: String) =
        File(System.getProperty(property)?.takeIf { it.isNotEmpty() } ?: default)
}
