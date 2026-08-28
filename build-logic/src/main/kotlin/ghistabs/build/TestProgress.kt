package ghistabs.build

import ghistabs.build.Fixtures.Companion.fixtures
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private val STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")
private val COARSE_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")

/**
 * Per-test events and a final summary on the console, with each run's reports under its own timestamped
 * dir — concurrent runs otherwise collide on the shared `in-progress-results-generic.bin`.
 *
 * [fixtures] drives the progress + ETA line; inert for tasks with no generated classes.
 */
fun Test.reportWithConsoleSummary(reportName: String) {
    val stamp = LocalDateTime.now().format(STAMP) + "-${ProcessHandle.current().pid()}"
    val buildDir = project.layout.buildDirectory
    binaryResultsDirectory.set(buildDir.dir("test-results/$reportName/$stamp/binary"))
    reports {
        junitXml.outputLocation.set(buildDir.dir("test-results/$reportName/$stamp"))
        html.outputLocation.set(buildDir.dir("reports/tests/$reportName/$stamp"))
    }
    testLogging {
        events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED)
        exceptionFormat = TestExceptionFormat.FULL
        showCauses = true
        showStackTraces = true
    }
    // UP-TO-DATE prints nothing, which reads as a silent no-op.
    outputs.upToDateWhen { false }

    archivePreviousResults(buildDir.dir("test-output/results").get().asFile, stamp)
    liveProgress(reportName, reports.html.outputLocation)
}

/**
 * LiveTestReporter and ExpectedToFailExtension (JUnit SPI) append per-fork result files to `results/`,
 * which should show only the current run — so archive the previous one rather than deleting it. The
 * audits read those dumps, and a stale one misrepresents the corpus.
 */
private fun Test.archivePreviousResults(resultsDir: java.io.File, stamp: String) {
    val history = resultsDir.resolveSibling("results-history")
    doFirst {
        if (resultsDir.isDirectory && resultsDir.list()?.isNotEmpty() == true) {
            // The previous run's own `.run-stamp`, not now(); mtime for runs that never wrote one.
            val prev = resultsDir.resolve(".run-stamp").takeIf { it.isFile }?.readText()?.trim()
                ?: LocalDateTime.ofInstant(Instant.ofEpochMilli(resultsDir.lastModified()), ZoneId.systemDefault())
                    .format(COARSE_STAMP)
            history.mkdirs()
            resultsDir.renameTo(history.resolve(prev))
        }
        resultsDir.mkdirs()
        resultsDir.resolve(".run-stamp").writeText(stamp)
    }
}

/** ETA from observed throughput, so it self-adjusts to the fork count. */
private fun Test.liveProgress(reportName: String, htmlDir: DirectoryProperty) {
    val failures = mutableListOf<String>()
    val runStart = AtomicLong(0L)
    val done = AtomicInteger(0)
    fun hms(ms: Long) = "%dm%02ds".format(ms / 60000, (ms / 1000) % 60)

    addTestListener(object : TestListener {
        override fun beforeSuite(suite: TestDescriptor) {
            runStart.compareAndSet(0L, System.currentTimeMillis())
        }

        override fun beforeTest(testDescriptor: TestDescriptor) = Unit

        override fun afterTest(d: TestDescriptor, result: TestResult) {
            if (result.resultType == TestResult.ResultType.FAILURE) failures += "${d.className}.${d.displayName}"
        }

        override fun afterSuite(suite: TestDescriptor, result: TestResult) {
            val fixtures = project.fixtures
            // Matching known FQNs excludes root/fork suites.
            val known = suite.className?.let { fixtures.labels[it] }
            if (known != null) {
                val n = done.incrementAndGet()
                val elapsed = System.currentTimeMillis() - runStart.get()
                val planned = fixtures.plannedTotal
                val eta = if (n < planned) (elapsed.toDouble() / n * (planned - n)).toLong() else 0L
                logger.lifecycle(
                    "  ✓ [%d/%d] %s — [%dP:%dF:%dS] in %ds | elapsed %s, ETA ~%s".format(
                        n, planned, known,
                        result.successfulTestCount, result.failedTestCount, result.skippedTestCount,
                        (result.endTime - result.startTime) / 1000, hms(elapsed), hms(eta),
                    ),
                )
            }
            if (suite.parent != null) return
            logger.lifecycle(
                "\n$reportName: ${result.resultType} — ${result.testCount} tests, " +
                    "${result.successfulTestCount} passed, ${result.failedTestCount} failed, " +
                    "${result.skippedTestCount} skipped",
            )
            failures.forEach { logger.lifecycle("  FAILED $it") }
            logger.lifecycle("HTML report: ${htmlDir.get().asFile}/index.html")
            logger.lifecycle(
                "Per-test results (status + skip reasons + setUp aborts): cat build/test-output/results/*.txt",
            )
        }
    })
}
