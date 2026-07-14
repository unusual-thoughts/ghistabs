import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.zip.ZipFile

plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.serialization") version "2.3.21"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.14.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("junit:junit:4.13.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
}

// Add Ghidra test JARs for integration tests (AbstractGhidraHeadlessIntegrationTest)
val ghidraInstallDirForTests =
    System.getenv("GHIDRA_INSTALL_DIR") ?: project.properties["GHIDRA_INSTALL_DIR"]?.toString() ?: "/opt/ghidra"

dependencies {
    testImplementation(
        fileTree(
            mapOf(
                "dir" to "$ghidraInstallDirForTests/Ghidra/Features/Base/lib",
                "include" to "Base.jar",
            ),
        ),
    )
    // Add Ghidra Test JARs for AbstractGhidraHeadlessIntegrationTest.
    // Resolves test harness dependencies from standard Ghidra installation paths.
    testImplementation(
        fileTree(
            mapOf(
                "dir" to "$ghidraInstallDirForTests/Ghidra/Test",
                "include" to listOf("**/lib/*.jar"),
            ),
        ),
    )
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
}

ktlint {
    additionalEditorconfig.set(
        mapOf("ktlint_standard_no-wildcard-imports" to "disabled"),
    )
}

// Don't copy `binaries/` into build/resources/test/. It's a ~21M
// pile of manually-placed test fixtures that integration tests open
// directly via File("src/test/resources/binaries/…"); copying it to the
// classpath just bloats the build dir. (Generated test outputs —
// records, logs, harvest dumps — already live under build/test-output/
// so they aren't a concern here. The extension zip excludes src/**
// regardless, so this filter is purely about build-dir hygiene.)
tasks.processTestResources {
    exclude("binaries/**")
}

tasks.test {
    useJUnitPlatform { excludeTags("integration", "probe") }
    testLogging {
        events("passed", "skipped", "failed")
    }
}

// Print per-test events + a final pass/fail/skip summary to the console of the same command
// that ran the tests (no XML/HTML spelunking), and archive each run under a per-invocation
// timestamped dir so a later run never clobbers an earlier one — and two concurrent runs don't
// collide on the shared `in-progress-results-generic.bin` (the NoSuchFileException we hit).
fun Test.reportWithConsoleSummary(name: String) {
    val stamp = LocalDateTime.now()
        .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")) +
        "-${ProcessHandle.current().pid()}"
    binaryResultsDirectory.set(project.layout.buildDirectory.dir("test-results/$name/$stamp/binary"))
    reports {
        junitXml.outputLocation.set(project.layout.buildDirectory.dir("test-results/$name/$stamp"))
        html.outputLocation.set(project.layout.buildDirectory.dir("reports/tests/$name/$stamp"))
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

    val log = logger
    val htmlDir = reports.html.outputLocation
    val failures = mutableListOf<String>()
    addTestListener(object : TestListener {
        override fun beforeSuite(suite: TestDescriptor) = Unit
        override fun beforeTest(testDescriptor: TestDescriptor) = Unit
        override fun afterTest(d: TestDescriptor, result: TestResult) {
            if (result.resultType == TestResult.ResultType.FAILURE) failures += "${d.className}.${d.displayName}"
        }
        override fun afterSuite(suite: TestDescriptor, result: TestResult) {
            if (suite.parent != null) return
            log.lifecycle(
                "\n$name: ${result.resultType} — ${result.testCount} tests, ${result.successfulTestCount} passed, " +
                    "${result.failedTestCount} failed, ${result.skippedTestCount} skipped",
            )
            failures.forEach { log.lifecycle("  FAILED $it") }
            log.lifecycle("HTML report: ${htmlDir.get().asFile}/index.html")
        }
    })
}

// Shared config for the headless-Ghidra test tasks: classpath, one-Ghidra-per-fork parallelism,
// -Pfixture/-PregenerateBaselines wiring, JVM args, and the console summary + archived reports.
// JVM args mirror ~/git/ghidra/gradle/javaTestProject.gradle:initTestJVM so Ghidra's
// HeadlessGhidraApplicationConfiguration boots cleanly under JDK 21. Ghidra's Application bootstrap
// is idempotent, so classes in one JVM share one install; we don't fork per class (forkEvery=0) and
// parallelise across forks instead. Each fork needs a real heap — loading a fixture + autoanalysis
// overflows the -Xmx512m default and crashes the worker with a NoSuchFileException on the result bin.
fun Test.headlessGhidraConfig(reportName: String) {
    group = "verification"
    reportWithConsoleSummary(reportName)
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    shouldRunAfter("test")
    forkEvery = 0
    maxParallelForks = (Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 4)
    maxHeapSize = "2g"
    // -Pfixture=<exact filename> narrows the fixture set (at the source, via IntegrationFixtures).
    systemProperty("fixtureFilter", providers.gradleProperty("fixture").getOrElse(""))
    // -PregenerateBaselines=true rewrites baseline JSONs from observed counters instead of asserting.
    systemProperty("regenerateBaselines", providers.gradleProperty("regenerateBaselines").getOrElse(""))
    jvmArgs(
        // Ghidra installs its own ObjectInputFilter factory; under JDK 21 it must be declared at JVM
        // startup, otherwise the BuiltinFilterFactory wins the race.
        "-Djdk.serialFilterFactory=ghidra.framework.remote.GhidraSerialFilterFactory",
        "-DSystemUtilities.isTesting=true",
        "-Djava.awt.headless=true",
        "-Dfile.encoding=UTF8",
        "-Duser.country=US",
        "-Duser.language=en",
        "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
        "--add-opens=java.desktop/sun.awt=ALL-UNNAMED",
        "--add-opens=java.desktop/sun.swing=ALL-UNNAMED",
        "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
        "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
        "--add-opens=java.desktop/javax.swing.text=ALL-UNNAMED",
    )
}

val integrationTest =
    tasks.register<Test>("integrationTest") {
        description = "Real-binary assertion tests against binary fixtures (@Tag(\"integration\"))"
        useJUnitPlatform { includeTags("integration") }
        headlessGhidraConfig("integrationTest")
    }

// Diagnostic generators (degradation dumps, source skeletons, type probes) — @Tag("probe"), split
// out of `integrationTest` so they don't run in CI. Run on demand, narrow with -Pfixture=<name>.
val probeDump =
    tasks.register<Test>("probeDump") {
        description = "Run @Tag(\"probe\") diagnostic dumps (not part of integrationTest)"
        useJUnitPlatform { includeTags("probe") }
        headlessGhidraConfig("probeDump")
    }

// List every test class grouped by its tag (unit / integration / probe) with its package + file, so
// tests are discoverable even though integration/probe tests are co-located in their SUT's package
// rather than a dedicated folder. Source scan — no compile/boot needed.
tasks.register("listTests") {
    group = "verification"
    description = "List test classes grouped by tag (unit/integration/probe)"
    val testRoot = layout.projectDirectory.dir("src/test/kotlin").asFile
    doLast {
        val classRe = Regex("""(?m)^(?:internal |abstract )?class (\w+)""")
        val pkgRe = Regex("""(?m)^package ([\w.]+)""")
        val tagRe = Regex("""@Tag\("(\w+)"\)""")
        val testRe = Regex("""@(?:Test|ParameterizedTest|ParameterizedClass)\b""")
        val byTag = sortedMapOf<String, MutableList<String>>()
        testRoot.walkTopDown().filter { it.extension == "kt" }.forEach { f ->
            val text = f.readText()
            if (!testRe.containsMatchIn(text)) return@forEach // skip helpers with no test methods
            val cls = classRe.find(text)?.groupValues?.get(1) ?: return@forEach
            val pkg = pkgRe.find(text)?.groupValues?.get(1).orEmpty()
            val tag = tagRe.find(text)?.groupValues?.get(1) ?: "unit"
            val methods = testRe.findAll(text).count()
            byTag.getOrPut(tag) { mutableListOf() }.add("  $pkg.$cls  ($methods tests)  ${f.relativeTo(projectDir)}")
        }
        byTag.forEach { (tag, rows) ->
            logger.lifecycle("\n$tag (${rows.size}):")
            rows.sorted().forEach(logger::lifecycle)
        }
        logger.lifecycle("\nRun: ./gradlew test | integrationTest [-Pfixture=<name>] | probeDump")
    }
}

val ghidraInstallDir =
    System.getenv("GHIDRA_INSTALL_DIR") ?: project.properties["GHIDRA_INSTALL_DIR"]?.toString() ?: "/opt/ghidra"

apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")

tasks.register("installExtension") {
    group = "ghidra"
    description = "Build and install the extension into the Ghidra user extensions directory"
    dependsOn("buildExtension")

    val distroPrefix = project.extra["DISTRO_PREFIX"].toString()
    val releaseName = project.extra["RELEASE_NAME"].toString()
    val projectName = project.name
    val buildExtensionZip = (tasks.named("buildExtension").get() as Zip).archiveFile

    doLast {
        val userDir: File = System.getenv("GHIDRA_USER_DIR")?.let { File(it) } ?: run {
            val dirName = "${distroPrefix}_$releaseName" // e.g. ghidra_12.0.4_DEV
            val home = System.getProperty("user.home")
            val modern = File("$home/.config/ghidra/$dirName")
            val legacy = File("$home/.ghidra/.$dirName")
            when {
                modern.exists() -> modern
                legacy.exists() -> legacy
                else -> throw GradleException(
                    "No Ghidra user dir found at $modern or $legacy. Set GHIDRA_USER_DIR to override.",
                )
            }
        }

        val targetDir = File(userDir, "Extensions")
        targetDir.mkdirs()

        val zip = buildExtensionZip.get().asFile
        val installedDir = File(targetDir, projectName)
        if (installedDir.exists()) {
            installedDir.deleteRecursively()
            logger.lifecycle("Removed previous install: $installedDir")
        }

        ZipFile(zip).use { zf ->
            for (entry in zf.entries()) {
                val out = File(targetDir, entry.name)
                if (entry.isDirectory) {
                    out.mkdirs()
                } else {
                    out.parentFile.mkdirs()
                    zf.getInputStream(entry).use { input ->
                        out.outputStream().use { output -> input.copyTo(output) }
                    }
                }
            }
        }
        logger.lifecycle("Installed ${zip.name} → $targetDir")
        logger.lifecycle("Restart Ghidra to load the new build.")
    }
}
