package ghidrakt.test

import org.junit.platform.launcher.LauncherSession
import org.junit.platform.launcher.LauncherSessionListener
import java.io.File

/**
 * Gives each test JVM a Ghidra temp directory of its own, before any test class touches Ghidra.
 *
 * Unset, every fork shares `<java.io.tmpdir>/<user>-ghidra`, and each call to Ghidra's
 * `ApplicationUtilities.getDefaultUserTempDir` resets that directory's permissions in two steps (write
 * off for everyone, then back on for the owner). A fork creating a file there in between — every
 * `ProgramBuilder` and program open does, through `Application.createTempFile` — fails with
 * `IOException: Permission denied`, so one parallel fork starting up could fail a test in another.
 *
 * Gradle names the root in [ROOT_PROPERTY]; each fork then takes `<root>/<worker id>` as
 * `application.tempdir`. Without the property (a test run from an IDE) nothing changes.
 */
class ForkTempDir : LauncherSessionListener {
    override fun launcherSessionOpened(session: LauncherSession) {
        assign(System.getProperty(ROOT_PROPERTY), System.getProperty(WORKER_PROPERTY))
    }

    companion object {
        const val ROOT_PROPERTY = "ghidrakt.forkTempRoot"
        const val GHIDRA_PROPERTY = "application.tempdir"
        private const val WORKER_PROPERTY = "org.gradle.test.worker"

        /** Points [GHIDRA_PROPERTY] at a fresh `<root>/<worker>`, unless it is set already or [root] isn't. */
        fun assign(root: String?, worker: String?): File? {
            if (root.isNullOrBlank() || !System.getProperty(GHIDRA_PROPERTY).isNullOrBlank()) return null
            val name = worker?.takeIf { it.isNotBlank() } ?: "pid-${ProcessHandle.current().pid()}"
            val dir = File(root, "worker-$name").absoluteFile
            // A rerun reuses the worker ids; start from nothing, as a fresh /tmp would.
            dir.deleteRecursively()
            check(dir.mkdirs()) { "Failed to create $dir" }
            System.setProperty(GHIDRA_PROPERTY, dir.path)
            return dir
        }
    }
}
