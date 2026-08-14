import com.sun.management.OperatingSystemMXBean
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import java.lang.management.ManagementFactory.getOperatingSystemMXBean
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.ZipFile
import kotlin.io.path.Path
import kotlin.io.path.relativeTo

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
val ghidraInstallDir = System.getenv("GHIDRA_INSTALL_DIR")
    ?: project.findProperty("GHIDRA_INSTALL_DIR")?.toString() ?: "/opt/ghidra"

dependencies {
    testImplementation(
        fileTree(
            mapOf(
                "dir" to "$ghidraInstallDir/Ghidra/Features/Base/lib",
                "include" to "Base.jar",
            ),
        ),
    )
    // Add Ghidra Test JARs for AbstractGhidraHeadlessIntegrationTest.
    // Resolves test harness dependencies from standard Ghidra installation paths.
    testImplementation(
        fileTree(
            mapOf(
                "dir" to "$ghidraInstallDir/Ghidra/Test",
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
    // Ghidra puts every installed extension's lib/ on one classpath, so the oldest kotlin-stdlib
    // among them can win over the one we ship. GhidraJupyterKotlin pins kotlinVersion=1.9.23
    // (its gradle.properties, still on main), which is the floor. Binding above it fails only at
    // runtime in the GUI — `sequenceOf(x)` resolved to the 2.x single-arg overload and threw
    // NoSuchMethodError, while every test passed against our own 2.3.21 on the test classpath.
    // apiVersion hides post-1.9 declarations from resolution, so that call goes back to the vararg
    // overload and the compiler also stops emitting coroutine spilling intrinsics 1.9.23 lacks.
    compilerOptions { apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9) }
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
    useJUnitPlatform { excludeTags("integration", "probe", "audit") }
    testLogging {
        events("passed", "skipped", "failed")
    }
    // -PlibstdcxxInclude=<dir> points the scan tests at a libstdc++ checkout other than the default
    // (~/git/gcc/libstdc++-v3/include). Absent, those tests skip: the corpus is not vendored.
    systemProperty("libstdcxxInclude", providers.gradleProperty("libstdcxxInclude").getOrElse(""))
}

/** Total RAM in MB */
val osMemoryMB get() = (getOperatingSystemMXBean() as OperatingSystemMXBean).totalMemorySize.shr(20).toInt()

// Flags every Ghidra JVM needs (mirrors ghidra's javaTestProject.gradle:initTestJVM).
val ghidraJvmArgs = listOf(
    "-Djava.awt.headless=true",
    "-Dfile.encoding=UTF8",
    "-Duser.country=US",
    "-Duser.language=en",
    "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.awt=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
)

// ── Fixture corpus ───────────────────────────────────────────────────────────────────────────
// The binaries directory is the corpus (IntegrationFixtures.ALL lists it at runtime); gradle
// schedules whole classes onto forks, so one generated class per fixture × mode is what parallelises.

/** Analyzer modes each fixture is generated for — mirrors ghistabs.Mode. */
val fixtureModes = listOf("CONCURRENT", "AFTER")

/** Every fixture binary on disk, sorted. `.md` is the folder's own README, not a fixture. */
val fixtureBinaries by lazy {
    layout.projectDirectory.dir("src/test/resources/binaries").asFile
        .listFiles()?.filter { it.isFile && it.extension != "md" }?.map { it.name }?.sorted().orEmpty()
}

/** Fixture filename + analyzer mode -> generated class name. Shared by generator, filter, listener. */
fun fixtureClassName(binary: String, mode: String) =
    binary.split(Regex("[^A-Za-z0-9]+")).filter { it.isNotEmpty() }.joinToString("") { part ->
        part.replaceFirstChar { it.uppercase() }
    } + mode.lowercase().replaceFirstChar { it.uppercase() } + "Test"

/** `-Pfixture=<file>[,…]`, defaulting to the whole corpus. */
val selectedFixtures get() = providers.gradleProperty("fixture").orNull.orEmpty()
    .split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { fixtureBinaries }

/** `-Pmode=CONCURRENT|AFTER`, defaulting to both. */
val selectedModes get() = providers.gradleProperty("mode").orNull.orEmpty()
    .split(',').map { it.trim().uppercase() }.filter { it.isNotEmpty() }.ifEmpty { fixtureModes }

val generateFixtureTests = tasks.register("generateFixtureTests") {
    description = "Generate one StabsImportRegressionBase subclass per fixture binary"
    val outDir = layout.buildDirectory.dir("generated/sources/fixtureTests/kotlin")
    // Listing is an input so adding/removing a binary regenerates; the task is cheap either way.
    inputs.property("fixtures", provider { fixtureBinaries })
    outputs.dir(outDir)
    doLast {
        val root = outDir.get().asFile
        root.deleteRecursively()
        root.resolve("ghistabs/fixtures").mkdirs()
        fixtureBinaries.forEach { binary ->
            fixtureModes.forEach { mode ->
                val cls = fixtureClassName(binary, mode)
                // ktlint wants the super type inline when it fits 120 cols, wrapped when it doesn't.
                val args = """("$binary", Mode.$mode)"""
                val oneLine = "class $cls : StabsImportRegressionBase$args"
                root.resolve("ghistabs/fixtures/$cls.kt").writeText(
                    listOf(
                        "// GENERATED by :generateFixtureTests from src/test/resources/binaries — do not edit.",
                        "package ghistabs.fixtures",
                        "",
                        "import ghistabs.Mode",
                        "import ghistabs.StabsImportRegressionBase",
                        "",
                        if (oneLine.length <= 120) oneLine else "class $cls :\n    StabsImportRegressionBase$args",
                    ).joinToString("\n", postfix = "\n"),
                )
            }
        }
        logger.lifecycle("generateFixtureTests: ${fixtureBinaries.size * fixtureModes.size} fixture classes")
    }
}

kotlin.sourceSets.test { kotlin.srcDir(generateFixtureTests) }

// Print per-test events + a final pass/fail/skip summary to the console of the same command
// that ran the tests (no XML/HTML spelunking), and archive each run under a per-invocation
// timestamped dir so a later run never clobbers an earlier one — and two concurrent runs don't
// collide on the shared `in-progress-results-generic.bin` (the NoSuchFileException we hit).
fun Test.reportWithConsoleSummary(name: String) {
    val stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")) +
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

    // LiveTestReporter (JUnit SPI, runs in-fork) appends per-fork result files here; a run's
    // `cat build/test-output/results/*.txt` should show only that run, so before each run archive the
    // previous results into a timestamped backup rather than deleting them. Captured as Files (not a
    // `project` ref) to stay configuration-cache friendly.
    val resultsDir = project.layout.buildDirectory.dir("test-output/results").get().asFile
    val resultsHistory = project.layout.buildDirectory.dir("test-output/results-history").get().asFile
    doFirst {
        if (resultsDir.isDirectory && resultsDir.list()?.isNotEmpty() == true) {
            // Archive under the PREVIOUS run's own stamp (each run records its `.run-stamp`), not
            // now() — tagging old results with the current time would be a lie. Fall back to the
            // results' mtime for pre-existing runs that never wrote a stamp.
            val prev = resultsDir.resolve(".run-stamp").takeIf { it.isFile }?.readText()?.trim()
                ?: LocalDateTime.ofInstant(
                    Instant.ofEpochMilli(resultsDir.lastModified()),
                    ZoneId.systemDefault(),
                ).format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
            resultsHistory.mkdirs()
            resultsDir.renameTo(resultsHistory.resolve(prev))
        }
        resultsDir.mkdirs()
        resultsDir.resolve(".run-stamp").writeText(stamp) // tag THIS run so the next archive is accurate
    }

    val htmlDir = reports.html.outputLocation
    val failures = mutableListOf<String>()

    // Live progress + ETA for the slow corpus; ETA uses observed throughput, so it self-adjusts
    // to the fork count. Inert for the unit-test task, which has no generated classes.
    val plannedTotal = (selectedFixtures.size * selectedModes.size).coerceAtLeast(1)
    // Generated class FQN -> "fixture/MODE" label, via the generator's own naming.
    val suiteLabels = fixtureBinaries
        .flatMap { b -> fixtureModes.map { m -> "ghistabs.fixtures.${fixtureClassName(b, m)}" to "$b/$m" } }
        .toMap()
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
            val known = suite.className?.let { suiteLabels[it] }
            if (known != null) {
                val n = done.incrementAndGet()
                val elapsed = System.currentTimeMillis() - runStart.get()
                val eta = if (n < plannedTotal) (elapsed.toDouble() / n * (plannedTotal - n)).toLong() else 0L
                logger.lifecycle(
                    "  ✓ [%d/%d] %s — [%dP:%dF:%dS] in %ds | elapsed %s, ETA ~%s".format(
                        n, plannedTotal, known,
                        result.successfulTestCount, result.failedTestCount, result.skippedTestCount,
                        (result.endTime - result.startTime) / 1000, hms(elapsed), hms(eta),
                    ),
                )
            }
            if (suite.parent != null) return
            logger.lifecycle(
                "\n$name: ${result.resultType} — ${result.testCount} tests, ${result.successfulTestCount} passed, " +
                    "${result.failedTestCount} failed, ${result.skippedTestCount} skipped",
            )
            failures.forEach { logger.lifecycle("  FAILED $it") }
            logger.lifecycle("HTML report: ${htmlDir.get().asFile}/index.html")
            logger.lifecycle(
                "Per-test results (status + skip reasons + setUp aborts): cat build/test-output/results/*.txt",
            )
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
fun Test.headlessGhidraConfig(reportName: String, narrowGeneratedClasses: Boolean = false) {
    group = "verification"
    reportWithConsoleSummary(reportName)
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    shouldRunAfter("test")
    forkEvery = 0
    // Measured knee is 6 on 8 physical cores / 30GB (1016s, vs 1143s at 4 and 1047s at 8): past that,
    // extra forks buy stalls, not throughput — LLC is 4MB per CCX and a fork's working set doesn't fit.
    // Capped by RAM (~2.5GB/fork incl. heap) so a smaller CI box scales down instead of swapping.
    // -PmaxForks overrides; use 1 for perf work, where parallel forks jitter timings.
    maxParallelForks = providers.gradleProperty("maxForks").orNull?.toIntOrNull()
        ?: minOf(6, Runtime.getRuntime().availableProcessors() / 2, osMemoryMB / 2500).coerceAtLeast(1)
    maxHeapSize = "2g"
    // -Pfixture=<exact filename>[,…] narrows two ways: the system property still gates the base
    // class (skips a stray invocation), and the gradle filter drops the generated classes outright
    // so unselected fixtures never boot a JVM at all.
    systemProperty("fixtureFilter", providers.gradleProperty("fixture").getOrElse(""))
    // -PdisableAnalyzers=<name substring>[,…] turns those analyzers off, for A/B probe runs.
    systemProperty("disableAnalyzers", providers.gradleProperty("disableAnalyzers").getOrElse(""))
    // -PsourceRoot=<dir>[;<dir>] — local checkouts of the sources a fixture was built from, for the
    // probes that need ground truth. Falls back to the environment so CI and a laptop differ by
    // configuration rather than by code; absent, those probes skip.
    systemProperty(
        "sourceRoot",
        providers.gradleProperty("sourceRoot")
            .orElse(providers.environmentVariable("GHISTABS_SOURCE_ROOT"))
            .getOrElse(""),
    )
    // -Pfixture and -Pmode intersect, selecting generated classes by name. Only the regression suite
    // has generated classes: applying this to probeDump would intersect with its `--tests` pattern and
    // silently select nothing (Gradle ANDs commandLineIncludePatterns with the build-script filter).
    if (narrowGeneratedClasses && (selectedFixtures != fixtureBinaries || selectedModes != fixtureModes)) {
        filter {
            selectedFixtures.forEach { b ->
                selectedModes.forEach { m -> includeTestsMatching("ghistabs.fixtures.${fixtureClassName(b, m)}") }
            }
            isFailOnNoMatchingTests = false
        }
    }
    // -Pmode=CONCURRENT|AFTER narrows the analyzer execution mode similarly (blank = both).
    systemProperty("modeFilter", providers.gradleProperty("mode").getOrElse(""))
    // -PregenerateBaselines=true rewrites baseline JSONs from observed counters instead of asserting.
    systemProperty("regenerateBaselines", providers.gradleProperty("regenerateBaselines").getOrElse(""))
    jvmArgs(
        ghidraJvmArgs +
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
    providers.gradleProperty("jfr").orNull?.let { jfr ->
        val path = jfr.ifBlank { "${layout.buildDirectory.get().asFile}/test-output/jfr/$reportName-%p.jfr" }
        // JFR aborts JVM startup rather than create a missing directory.
        file(path).parentFile?.mkdirs()
        jvmArgs("-XX:StartFlightRecording=settings=profile,dumponexit=true,maxsize=500m,filename=$path")
    }
}

tasks.register<Test>("integrationTest") {
    description = "Real-binary assertion tests against binary fixtures (@Tag(\"integration\"))"
    useJUnitPlatform { includeTags("integration") }
    headlessGhidraConfig("integrationTest", narrowGeneratedClasses = true)
    finalizedBy(auditWhitelist)
}

// Diagnostic generators (degradation dumps, source skeletons, type probes) — @Tag("probe"), split
// out of `integrationTest` so they don't run in CI. Run on demand, narrow with -Pfixture=<name>.
// Corpus-level audits (@Tag("audit")) read the per-fixture dumps integrationTest produces, so they
// must run after it — as ordinary integration classes they raced their own inputs and skipped.
val auditWhitelist = tasks.register<Test>("auditWhitelist") {
    description = "Corpus-level audits over the dumps integrationTest wrote"
    useJUnitPlatform { includeTags("audit") }
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    outputs.upToDateWhen { false }
    testLogging { events("passed", "skipped", "failed") }
}

tasks.register<Test>("probeDump") {
    description = "Run @Tag(\"probe\") diagnostic dumps (not part of integrationTest)"
    useJUnitPlatform { includeTags("probe") }
    headlessGhidraConfig("probeDump")
}

// One fixture × one analyzer setting per invocation — a full load+autoanalysis each — writing a roster
// per setting; `diff`ing the two is the with/without comparison. Its own task because `integrationTest`
// narrows generated classes and Gradle ANDs that with `--tests`, which would select nothing at all and
// still report SUCCESS.
tasks.register<Test>("noReturnTest") {
    description =
        "Non-returning roster for one fixture (-Pfixture=<file>; add -PdisableAnalyzers=reachability for before)"
    useJUnitPlatform { includeTags("integration") }
    headlessGhidraConfig("noReturnTest")
    filter { includeTestsMatching("ghistabs.NoReturnFixtureIntegrationTest") }
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

apply(from = File(ghidraInstallDir).resolve("support/buildExtension.gradle"))

// The freestanding headless CLI lives in its own `cli` source set so neither it nor its clikt
// dependency land on the main runtimeClasspath — buildExtension's copyDependencies would otherwise
// bundle clikt into the extension zip's lib/. `cliImplementation` inherits main's deps (`api` carries
// the Ghidra jars, `implementation` the serialization libs) plus the main output and clikt.
val cli = sourceSets.create("cli")
configurations["cliImplementation"].extendsFrom(configurations["api"], configurations["implementation"])

// Friend the cli compilation to main so it sees main's `internal` API (Harvester.harvest etc.) —
// the same association the test compilation gets automatically.
kotlin.target.compilations.named("cli") {
    associateWith(kotlin.target.compilations.getByName("main"))
}

dependencies {
    "cliImplementation"(sourceSets["main"].output)
    "cliImplementation"("com.github.ajalt.clikt:clikt:4.4.0")
}

// We boot Ghidra from a flat classpath rather than via `ghidra.Ghidra`/GhidraClassLoader, so — like the
// headless test harness — we need the java.base concurrency add-opens under JDK 21. Unlike that harness
// we DON'T set `-Djdk.serialFilterFactory`: HeadlessGhidraApplicationConfiguration installs the Ghidra
// factory programmatically (the test harness only sets the -D because its own serialization runs before
// init), and setting both throws "filter factory already instantiated".
val cliJvmArgs = ghidraJvmArgs + listOf("-Xmx2g", "--enable-native-access=ALL-UNNAMED")

// Run the CLI in-process against the `cli` runtime classpath (Ghidra jars + main output + clikt).
// Pass args with `-Pargs="skeleton <binary> -d out"`.
tasks.register<JavaExec>("runCli") {
    group = "application"
    description = "Run the headless skeleton/decomp CLI (ghistabs.cli.MainKt)"
    dependsOn(cli.classesTaskName)
    classpath = cli.runtimeClasspath
    mainClass.set("ghistabs.cli.MainKt")
    jvmArgs(cliJvmArgs)
    args = providers.gradleProperty("args").getOrElse("").split(" ").filter { it.isNotEmpty() }
}

// The CLI's own code (main + cli output) as a single jar, for the standalone launcher's lib dir.
val cliJar = tasks.register<Jar>("cliJar") {
    description = "Generate the JAR for headless skeleton/decomp CLI"
    archiveBaseName.set("ghidra-stabs-cli")
    from(sourceSets["main"].output, sourceSets["cli"].output)
}

// Emit a standalone launcher (build/cli/ghidra-stabs) that runs the CLI without Gradle. Everything
// outside Ghidra — our code jar plus the maven deps — is packaged into build/cli/lib/ (not left in the
// Gradle cache), referenced relative to the script's own location so build/cli/ can be moved as a unit.
// Only the Ghidra jars stay referenced in place (absolute, under GHIDRA_INSTALL_DIR). Regenerate after a
// Ghidra reinstall. `./gradlew buildCli` → run `build/cli/ghidra-stabs skeleton <binary> -d out`.
tasks.register("buildCli") {
    group = "application"
    description = "Generate a standalone launcher script for the CLI at build/cli/ghidra-stabs"
    dependsOn(cliJar)
    val ghidraRoot = Path(ghidraInstallDir)
    val cliJarFile = cliJar.flatMap { it.archiveFile }
    val cliDir = layout.buildDirectory.dir("cli")
    outputs.dir(cliDir)
    doLast {
        val lib = cliDir.get().dir("lib").asFile
        lib.deleteRecursively()
        lib.mkdirs()
        // Package our code + every non-Ghidra runtime jar (clikt tree, kotlin-stdlib, serialization)
        // into lib/; the Ghidra jars are kept out and referenced in place.
        cliJarFile.get().asFile.copyTo(File(lib, "ghidra-stabs-cli.jar"))

        val ghidraJars = cli.runtimeClasspath.files
            .map { it.toPath() }
            .filter { it.startsWith(ghidraRoot) }
            .map { it.relativeTo(ghidraRoot) }
            .map { Path($$"$GHIDRA_INSTALL_DIR").resolve(it) }

        for (cp in cli.runtimeClasspath.files) {
            if (cp.isFile && !cp.toPath().startsWith(ghidraRoot)) {
                cp.copyTo(File(lib, cp.name), overwrite = true)
            }
        }

        cliDir.get().file("ghidra-stabs").asFile.apply {
            writeText(
                buildString {
                    appendLine("#!/bin/sh")
                    appendLine("# Generated by `gradle buildCli`. lib/ is self-contained.")
                    appendLine("GHIDRA_INSTALL_DIR=\"$ghidraInstallDir\"")
                    appendLine($$"dir=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)")
                    appendLine("exec java ${cliJvmArgs.joinToString(" ")} \\")
                    appendLine($$"  -cp \"$dir/lib/*:$${ghidraJars.joinToString(":")}\" \\")
                    appendLine("  ghistabs.cli.MainKt \"$@\"")
                },
            )
            setExecutable(true)
            logger.lifecycle("Wrote $this (+ ${lib.listFiles()?.size ?: 0} jars in lib/)")
        }
    }
}

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

// buildExtension zips the whole projectDir, which here is full of uncommitted research corpora, a git
// worktree (prout/), IDE dirs and docs. Rather than exclude that pile, whitelist the actual extension
// content. Patterns are matched relative to each of buildExtension's copy specs, so the top-level tree
// (Module.manifest, lib/, ghidra_scripts/…) is anchored, while the generated jar and source zip — added
// by separate specs straight into lib/ — are matched by their bare filenames.
tasks.named<Zip>("buildExtension") {
    includeEmptyDirs = false
    include(
        "extension.properties",
        "Module.manifest",
        "README.md",
        "lib/**",
        "ghidra_scripts/**",
        "${project.name}.jar",
        "${project.name}-src.zip",
    )
}
