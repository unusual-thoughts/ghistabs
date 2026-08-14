package ghistabs.build

import com.sun.management.OperatingSystemMXBean
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.TaskProvider
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.get
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.register
import java.lang.management.ManagementFactory.getOperatingSystemMXBean

/**
 * Flags every Ghidra JVM needs, headless test or CLI — mirrors
 * `~/git/ghidra/gradle/javaTestProject.gradle:initTestJVM` so Ghidra's
 * HeadlessGhidraApplicationConfiguration boots cleanly under JDK 21.
 */
val GHIDRA_JVM_ARGS = listOf(
    "-Djava.awt.headless=true",
    "-Dfile.encoding=UTF8",
    "-Duser.country=US",
    "-Duser.language=en",
    "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.awt=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
)

/** Total RAM in MB. */
private val osMemoryMB get() = (getOperatingSystemMXBean() as OperatingSystemMXBean).totalMemorySize.shr(20).toInt()

/**
 * Shared config for the headless-Ghidra test tasks: classpath, one-Ghidra-per-fork parallelism,
 * `-Pfixture`/`-PregenerateBaselines` wiring, JVM args, and the console summary + archived reports.
 *
 * Ghidra's Application bootstrap is idempotent, so classes in one JVM share one install; we don't fork
 * per class (`forkEvery = 0`) and parallelise across forks instead. Each fork needs a real heap —
 * loading a fixture + autoanalysis overflows the -Xmx512m default and crashes the worker with a
 * NoSuchFileException on the result bin.
 */
fun Test.headlessGhidraConfig(reportName: String, fixtures: Fixtures, narrowGeneratedClasses: Boolean = false) {
    val testSourceSet = project.extensions.getByType<JavaPluginExtension>().sourceSets["test"]
    val props = project.providers

    group = "verification"
    reportWithConsoleSummary(reportName, fixtures)
    testClassesDirs = testSourceSet.output.classesDirs
    classpath = testSourceSet.runtimeClasspath
    shouldRunAfter("test")
    forkEvery = 0
    // Measured knee is 6 on 8 physical cores / 30GB (1016s, vs 1143s at 4 and 1047s at 8): past that,
    // extra forks buy stalls, not throughput — LLC is 4MB per CCX and a fork's working set doesn't fit.
    // Capped by RAM (~2.5GB/fork incl. heap) so a smaller CI box scales down instead of swapping.
    // -PmaxForks overrides; use 1 for perf work, where parallel forks jitter timings.
    maxParallelForks = props.gradleProperty("maxForks").orNull?.toIntOrNull()
        ?: minOf(6, Runtime.getRuntime().availableProcessors() / 2, osMemoryMB / 2500).coerceAtLeast(1)
    maxHeapSize = "2g"
    // -Pfixture=<exact filename>[,…] narrows two ways: the system property still gates the base
    // class (skips a stray invocation), and the gradle filter drops the generated classes outright
    // so unselected fixtures never boot a JVM at all.
    systemProperty("fixtureFilter", props.gradleProperty("fixture").getOrElse(""))
    // -PdisableAnalyzers=<name substring>[,…] turns those analyzers off, for A/B probe runs.
    systemProperty("disableAnalyzers", props.gradleProperty("disableAnalyzers").getOrElse(""))
    // -PsourceRoot=<dir>[;<dir>] — local checkouts of the sources a fixture was built from, for the
    // probes that need ground truth. Falls back to the environment so CI and a laptop differ by
    // configuration rather than by code; absent, those probes skip.
    systemProperty(
        "sourceRoot",
        props.gradleProperty("sourceRoot").orElse(props.environmentVariable("GHISTABS_SOURCE_ROOT")).getOrElse(""),
    )
    // -Pfixture and -Pmode intersect, selecting generated classes by name. Only the regression suite
    // has generated classes: applying this to probeDump would intersect with its `--tests` pattern and
    // silently select nothing (Gradle ANDs commandLineIncludePatterns with the build-script filter).
    if (narrowGeneratedClasses && fixtures.isNarrowed) {
        filter {
            fixtures.selectedClasses.forEach { includeTestsMatching(it) }
            isFailOnNoMatchingTests = false
        }
    }
    // -Pmode=CONCURRENT|AFTER narrows the analyzer execution mode similarly (blank = both).
    systemProperty("modeFilter", props.gradleProperty("mode").getOrElse(""))
    // -PregenerateBaselines=true rewrites baseline JSONs from observed counters instead of asserting.
    systemProperty("regenerateBaselines", props.gradleProperty("regenerateBaselines").getOrElse(""))
    jvmArgs(
        GHIDRA_JVM_ARGS +
            listOf(
                // Ghidra installs its own ObjectInputFilter factory; under JDK 21 it must be declared
                // at JVM startup, else the BuiltinFilterFactory wins the race.
                "-Djdk.serialFilterFactory=ghidra.framework.remote.GhidraSerialFilterFactory",
                "-DSystemUtilities.isTesting=true",
                "--add-opens=java.desktop/sun.swing=ALL-UNNAMED",
                "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
                "--add-opens=java.desktop/javax.swing.text=ALL-UNNAMED",
            ),
    )
    // -Pjfr[=<file>]: profile from JVM start. Read recordings with the jdk.jfr.consumer
    // RecordingFile API — `jfr print`/`jfr view` crash on Kotlin synthetic frames.
    props.gradleProperty("jfr").orNull?.let { jfr ->
        val buildDir = project.layout.buildDirectory.get().asFile
        val path = jfr.ifBlank { "$buildDir/test-output/jfr/$reportName-%p.jfr" }
        // JFR aborts JVM startup rather than create a missing directory.
        java.io.File(path).parentFile?.mkdirs()
        jvmArgs("-XX:StartFlightRecording=settings=profile,dumponexit=true,maxsize=500m,filename=$path")
    }
}

/**
 * Register a headless-Ghidra test task: [name] is both the task and the report directory, [tag] the
 * JUnit tag it runs. [configure] lands last, so it can narrow what [headlessGhidraConfig] set up.
 */
fun Project.registerHeadlessTest(
    name: String,
    description: String,
    tag: String,
    fixtures: Fixtures,
    narrowGeneratedClasses: Boolean = false,
    configure: Test.() -> Unit = {},
): TaskProvider<Test> = tasks.register<Test>(name) {
    this.description = description
    useJUnitPlatform { includeTags(tag) }
    headlessGhidraConfig(name, fixtures, narrowGeneratedClasses)
    configure()
}
