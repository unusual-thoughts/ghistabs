package ghistabs

import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.jupiter.api.extension.TestWatcher
import java.io.File
import java.util.Optional

/**
 * Live, greppable per-test reporting so outcomes — especially skip *reasons*, which gradle's
 * `TestResult` cannot surface — are readable without opening gradle's XML / binary event dumps.
 *
 * A JUnit5 [TestWatcher] (a plain `jupiter-api` extension, so it compiles without the platform
 * launcher and is invoked reliably), auto-registered for every test via
 * `META-INF/services/org.junit.jupiter.api.extension.Extension` +
 * `junit.jupiter.extensions.autodetection.enabled=true`. Each test appends one line to a per-fork
 * file under `build/test-output/results` (per-fork sidesteps cross-JVM append races; the gradle task
 * archives the dir before each run). Read a run with: cat that dir's txt files.
 * Line format: `STATUS  fixture/mode  testName[ — reason]`.
 */
class LiveTestReporter : TestWatcher {
    private val out = File("build/test-output/results/fork-${ProcessHandle.current().pid()}.txt")

    /** Walk enclosing contexts for the `binaryName=…, mode=…` invocation label so lines self-locate. */
    private fun where(context: ExtensionContext): String {
        var c: ExtensionContext? = context
        while (c != null) {
            invocation.find(c.displayName)?.let { return "${it.groupValues[1]}/${it.groupValues[2]}" }
            c = c.parent.orElse(null)
        }
        return "-"
    }

    private fun emit(status: String, context: ExtensionContext, note: String = "") {
        out.parentFile.mkdirs()
        out.appendText("%-5s %s  %s%s\n".format(status, where(context), context.displayName, note))
    }

    private fun oneLine(t: Throwable) = t.toString().lineSequence().first().take(300)

    override fun testSuccessful(context: ExtensionContext) = emit("PASS", context)
    override fun testFailed(context: ExtensionContext, cause: Throwable) = emit("FAIL", context, ": ${oneLine(cause)}")
    override fun testAborted(context: ExtensionContext, cause: Throwable) =
        emit("SKIP", context, " — ${cause.message?.take(300)}")
    override fun testDisabled(context: ExtensionContext, reason: Optional<String>) =
        emit("OFF", context, " — ${reason.orElse("")}")

    private companion object {
        val invocation = Regex("""binaryName=([^,]+), mode=(\w+)""")
    }
}
