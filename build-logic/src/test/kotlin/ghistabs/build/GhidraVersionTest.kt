package ghistabs.build

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * [GhidraVersion] picks which `src/main/kotlin-*sourcemap` and `src/compat/kotlin-*` variants compile,
 * and whether the test JVM names `GhidraSerialFilterFactory`. Getting it wrong doesn't fail here — it
 * fails as an unresolved reference, or as a test JVM that aborts before loading a class.
 */
class GhidraVersionTest {
    private infix fun String.atLeast(other: String) = GhidraVersion.of(this) >= GhidraVersion.of(other)

    @Test
    fun comparesComponentWiseRatherThanLexically() {
        // The string comparison "11.4.3" < "12" happens to agree; "9.2" > "12" is where it breaks.
        assertTrue("12.1.2" atLeast "9.2")
        assertFalse("9.2" atLeast "12")
    }

    @Test
    fun treatsMissingComponentsAsZero() {
        assertEquals(GhidraVersion(11, 3, 0), GhidraVersion.of("11.3"))
        assertTrue("12.1.2" atLeast "12.1")
        // 12.0.x is not 12.1: `checkValidReplacement` arrived in the minor, not the major.
        assertFalse("12.0.4" atLeast "12.1")
    }

    /** The three boundaries the build actually cuts on, against the installs they're cut for. */
    @Test
    fun placesTheRealInstallsOnTheRightSideOfEachBoundary() {
        assertFalse("10.4" atLeast "11.3") // no SourceFileManager
        assertTrue("11.4.3" atLeast "11.3")
        assertFalse("11.4.3" atLeast "12") // AutoImporter, not ProgramLoader
        assertTrue("12.1.2" atLeast "12")
    }

    @Test
    fun isInclusiveOfTheBoundary() {
        assertTrue("11.3" atLeast "11.3")
    }

    /** Ghidra's own `application.version` carries suffixes on non-release builds. */
    @Test
    fun toleratesNonNumericSuffixes() {
        assertEquals(GhidraVersion(12, 1, 0), GhidraVersion.of("12.1-DEV"))
    }
}
