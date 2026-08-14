package ghistabs.build

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
 * Print per-test events + a final pass/fail/skip summary to the console of the same command that ran
 * the tests (no XML/HTML spelunking), and archive each run under a per-invocation timestamped dir so a
 * later run never clobbers an earlier one — and two concurrent runs don't collide on the shared
 * `in-progress-results-generic.bin` (the NoSuchFileException we hit).
 *
 * [fixtures] drives the live progress + ETA line for the slow corpus runs. Inert for the unit-test
 * task, which has no generated classes for the labels to match.
 */
fun Test.reportWithConsoleSummary(reportName: String, fixtures: Fixtures) {
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
    // These take minutes and print nothing when UP-TO-DATE, which reads as a silent no-op; always
    // re-run so a fresh result + summary print every invocation.
    outputs.upToDateWhen { false }

    archivePreviousResults(buildDir.dir("test-output/results").get().asFile, stamp)
    liveProgress(reportName, fixtures, reports.html.outputLocation)
}

/**
 * LiveTestReporter (JUnit SPI, runs in-fork) appends per-fork result files to `results/`; catting that
 * directory should show only the current run, so before each run archive the previous results into a
 * timestamped backup rather than deleting them. Captured as Files (not a `project` ref) to stay
 * configuration-cache friendly.
 */
private fun Test.archivePreviousResults(resultsDir: java.io.File, stamp: String) {
    val history = resultsDir.resolveSibling("results-history")
    doFirst {
        if (resultsDir.isDirectory && resultsDir.list()?.isNotEmpty() == true) {
            // Archive under the PREVIOUS run's own stamp (each run records its `.run-stamp`), not
            // now() — tagging old results with the current time would be a lie. Fall back to the
            // results' mtime for pre-existing runs that never wrote a stamp.
            val prev = resultsDir.resolve(".run-stamp").takeIf { it.isFile }?.readText()?.trim()
                ?: LocalDateTime.ofInstant(Instant.ofEpochMilli(resultsDir.lastModified()), ZoneId.systemDefault())
                    .format(COARSE_STAMP)
            history.mkdirs()
            resultsDir.renameTo(history.resolve(prev))
        }
        resultsDir.mkdirs()
        resultsDir.resolve(".run-stamp").writeText(stamp) // tag THIS run so the next archive is accurate
    }
}

/** ETA uses observed throughput, so it self-adjusts to the fork count. */
private fun Test.liveProgress(reportName: String, fixtures: Fixtures, htmlDir: org.gradle.api.file.DirectoryProperty) {
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
            // One generated class == one unit of work; matching known FQNs excludes root/fork suites.
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
