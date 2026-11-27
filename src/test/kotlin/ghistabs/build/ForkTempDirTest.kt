package ghistabs.build

import ghidrakt.test.ForkTempDir
import ghidrakt.test.ForkTempDir.Companion.GHIDRA_PROPERTY
import ghidrakt.test.mustBe
import ghidrakt.test.mustBeFalse
import ghidrakt.test.mustBeNull
import ghidrakt.test.mustBeTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

// The `test` JVM got its own directory from the listener already; each case starts without one.
class ForkTempDirTest {
    private var assigned: String? = null

    @BeforeEach
    fun clear() {
        assigned = System.clearProperty(GHIDRA_PROPERTY)
    }

    @AfterEach
    fun restore() {
        assigned?.let { System.setProperty(GHIDRA_PROPERTY, it) } ?: System.clearProperty(GHIDRA_PROPERTY)
    }

    @Test
    fun eachWorkerGetsAnEmptyDirectoryOfItsOwn(@TempDir root: File) {
        File(root, "worker-7/stale").apply { parentFile.mkdirs() }.writeText("left by an earlier run")

        val dir = ForkTempDir.assign(root.path, "7")

        dir mustBe File(root, "worker-7")
        System.getProperty(GHIDRA_PROPERTY) mustBe dir!!.path
        dir.isDirectory.mustBeTrue()
        File(dir, "stale").exists().mustBeFalse()
        System.clearProperty(GHIDRA_PROPERTY)
        ForkTempDir.assign(root.path, "8") mustBe File(root, "worker-8")
    }

    @Test
    fun withoutARootOrWithAGhidraDirectorySetNothingChanges(@TempDir root: File) {
        ForkTempDir.assign("", "1").mustBeNull()
        System.getProperty(GHIDRA_PROPERTY).mustBeNull()

        System.setProperty(GHIDRA_PROPERTY, "/elsewhere")
        ForkTempDir.assign(root.path, "1").mustBeNull()
        System.getProperty(GHIDRA_PROPERTY) mustBe "/elsewhere"
        root.list()!!.size mustBe 0
    }
}
