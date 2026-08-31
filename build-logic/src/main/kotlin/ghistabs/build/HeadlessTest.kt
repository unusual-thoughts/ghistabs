package ghistabs.build

import com.sun.management.OperatingSystemMXBean
import ghistabs.build.Fixtures.Companion.fixtures
import org.gradle.api.Project
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.TaskProvider
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.get
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.register
import java.lang.management.ManagementFactory.getOperatingSystemMXBean

/** Mirrors ghidra's `javaTestProject.gradle:initTestJVM`. */
val GHIDRA_JVM_ARGS = listOf(
    "-Djava.awt.headless=true",
    "-Dfile.encoding=UTF8",
    "-Duser.country=US",
    "-Duser.language=en",
    "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.awt=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
)

val Project.headlessJvmArgs get() = GHIDRA_JVM_ARGS + listOfNotNull(
    // Must be declared at JVM startup, else the BuiltinFilterFactory wins the race. 12.0 added the
    // class; naming it on 11 aborts the test JVM before a single test class loads.
    "-Djdk.serialFilterFactory=ghidra.framework.remote.GhidraSerialFilterFactory"
        .takeIf { ghidraAtLeast("12") },
    "-DSystemUtilities.isTesting=true",
    "--add-opens=java.desktop/sun.swing=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing.text=ALL-UNNAMED",
)

val Project.sourceSets get() = extensions.getByType<SourceSetContainer>()

/** Total RAM in MB. */
private val osMemoryMB get() = (getOperatingSystemMXBean() as OperatingSystemMXBean).totalMemorySize.shr(20).toInt()

/**
 * Shared config for the headless-Ghidra test tasks. Ghidra's Application bootstrap is idempotent, so
 * classes share one install per JVM: no fork per class, parallelise across forks instead.
 */
fun Test.headlessGhidraConfig(reportName: String, narrowGeneratedClasses: Boolean = false) {
    val testSourceSet = project.sourceSets["test"]
    val props = project.providers

    group = "verification"
    reportWithConsoleSummary(reportName)
    testClassesDirs = testSourceSet.output.classesDirs
    classpath = testSourceSet.runtimeClasspath
    shouldRunAfter("test")
    forkEvery = 0
    // Measured knee is 6 on 8 physical cores / 30GB; past that forks buy stalls, not throughput.
    // Capped by RAM (~2.5GB/fork) so a smaller box scales down instead of swapping.
    maxParallelForks = props.gradleProperty("maxForks").orNull?.toIntOrNull()
        ?: minOf(6, Runtime.getRuntime().availableProcessors() / 2, osMemoryMB / 2500).coerceAtLeast(1)
    maxHeapSize = "2g"
    // -Pfixture=<exact filename>[,…] — the corpus `Fixtures` offers the hand-written
    // fixture-parameterised suites (NoReturnFixtureIntegrationTest picks its single binary this way).
    // It deliberately selects no test class: -Pregression is the axis that narrows the fixture matrix.
    systemProperty("fixtureFilter", props.gradleProperty("fixture").getOrElse(""))
    // -PdisableAnalyzers=<name substring>[,…] turns those analyzers off, for A/B probe runs.
    systemProperty("disableAnalyzers", props.gradleProperty("disableAnalyzers").getOrElse(""))
    // -PsourceRoot=<dir>[;<dir>] — checkouts of the sources a fixture was built from. Absent, the
    // probes needing ground truth skip.
    systemProperty(
        "sourceRoot",
        props.gradleProperty("sourceRoot").orElse(props.environmentVariable("GHISTABS_SOURCE_ROOT")).getOrElse(""),
    )
    val fixtures = project.fixtures
    // Only for the generated suite: Gradle ANDs this with `--tests`, so applying it elsewhere
    // silently selects nothing.
    if (narrowGeneratedClasses) {
        filter {
            // -Pmode. Always applied, since the default is a single mode; see [unselectedModeClasses]
            // for why the mode axis subtracts where the suite axis selects.
            fixtures.unselectedModeClasses.forEach { excludeTestsMatching(it) }
            // -Pregression[=<binary>[,…]] — the fixture matrix alone, narrowed to those binaries.
            // Absent, nothing is included and every other integration class runs alongside it.
            if (fixtures.regressionOnly) fixtures.selectedClasses.forEach { includeTestsMatching(it) }
            isFailOnNoMatchingTests = false
        }
    }
    // -Pmode=CONCURRENT|AFTER narrows the analyzer execution mode similarly (blank = both).
    systemProperty("modeFilter", props.gradleProperty("mode").getOrElse(""))
    // -PregenerateBaselines=true rewrites baseline JSONs from observed counters instead of asserting.
    systemProperty("regenerateBaselines", props.gradleProperty("regenerateBaselines").getOrElse(""))
    // -PignoreBaselines=true reports drift without failing; drifted fixtures still write their counters.
    systemProperty("ignoreBaselines", props.gradleProperty("ignoreBaselines").getOrElse(""))
    jvmArgs(project.headlessJvmArgs)
    // -Pjfr[=<file>]. Read recordings with the jdk.jfr.consumer API — `jfr print` crashes on Kotlin
    // synthetic frames.
    props.gradleProperty("jfr").orNull?.let { jfr ->
        val buildDir = project.layout.buildDirectory.get().asFile
        val path = jfr.ifBlank { "$buildDir/test-output/jfr/$reportName-%p.jfr" }
        // JFR aborts JVM startup rather than create a missing directory.
        java.io.File(path).parentFile?.mkdirs()
        jvmArgs("-XX:StartFlightRecording=settings=profile,dumponexit=true,maxsize=500m,filename=$path")
    }
}

/** [name] is both the task and its report directory. [configure] lands last, so it can narrow. */
fun Project.registerHeadlessTest(
    name: String,
    description: String,
    tag: String,
    narrowGeneratedClasses: Boolean = false,
    configure: Test.() -> Unit = {},
): TaskProvider<Test> = tasks.register<Test>(name) {
    this.description = description
    useJUnitPlatform { includeTags(tag) }
    headlessGhidraConfig(name, narrowGeneratedClasses)
    configure()
}
