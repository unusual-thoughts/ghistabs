import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import java.io.File
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
val ghidraInstallDir =
    System.getenv("GHIDRA_INSTALL_DIR") ?: project.properties["GHIDRA_INSTALL_DIR"]?.toString() ?: "/opt/ghidra"

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

    // Live per-fixture progress + ETA for the slow integration corpus (each fixture×mode is a full
    // load+autoanalysis+import). Planned count = (fixtures present on disk that pass -Pfixture) ×
    // (modes that pass -Pmode); ETA uses observed wall-clock throughput so it self-adjusts to how
    // many forks are actually running. Fires only for parameterized `binaryName=…, mode=…` suites,
    // so it's inert for the unit-test task.
    val binDir = project.layout.projectDirectory.dir("src/test/resources/binaries").asFile
    val fixtureSel = providers.gradleProperty("fixture").getOrElse("").split(",")
        .map { it.trim() }.filter { it.isNotEmpty() }
    val modeSel = providers.gradleProperty("mode").getOrElse("").split(",").map { it.trim() }.filter { it.isNotEmpty() }
    val plannedFixtures = fixtureSel.ifEmpty {
        binDir.listFiles()?.map { it.name } ?: emptyList()
    }.count { File(binDir, it).isFile }
    val plannedTotal = (plannedFixtures * (if (modeSel.isNotEmpty()) modeSel.size else 2)).coerceAtLeast(1)
    val invRe = Regex("""binaryName=([^,]+), mode=(\w+)""")
    val invocationSuite = Regex(""".*\[\d+]$""")
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
            // A parameterized-class invocation finishes as a suite named `<Class>[<n>]` with a null
            // className. gradle's `name` is only `StabsImportRegressionTest[1]`, but its `displayName`
            // carries the `binaryName=…, mode=…` args — pull the fixture/mode from there, falling back
            // to the bracketed name so the line still renders if that ever changes.
            if (suite.className == null && suite.name.matches(invocationSuite)) {
                val n = done.incrementAndGet()
                val label = invRe.find(suite.displayName)?.let { "${it.groupValues[1]}/${it.groupValues[2]}" }
                    ?: suite.name.substringAfterLast('.')
                val elapsed = System.currentTimeMillis() - runStart.get()
                val eta = if (n < plannedTotal) (elapsed.toDouble() / n * (plannedTotal - n)).toLong() else 0L
                logger.lifecycle(
                    "  ✓ [%d/%d] %s — [%dP:%dF:%dS] in %ds | elapsed %s, ETA ~%s".format(
                        n, plannedTotal, label,
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

// One test class per fixture binary, generated from the directory listing (the authoritative
// corpus — see IntegrationFixtures.ALL). Gradle schedules whole *classes* onto forks, so a single
// @ParameterizedClass over every fixture can never parallelise: one fork runs them all serially.
// A class per fixture lets maxParallelForks distribute them across JVMs, which also keeps each
// fixture's state process-isolated (JUnit-thread concurrency corrupts the shared PER_CLASS instance).
val fixturesDir = layout.projectDirectory.dir("src/test/resources/binaries")

/** Fixture filename (+ analyzer mode) -> generated class name. MUST match the filters below. */
fun fixtureClassName(binary: String, mode: String = "") =
    binary.split(Regex("[^A-Za-z0-9]+")).filter { it.isNotEmpty() }.joinToString("") { part ->
        part.replaceFirstChar { it.uppercase() }
    } + mode.lowercase().replaceFirstChar { it.uppercase() } + "Test"

/** The analyzer modes each fixture is generated for — mirrors ghistabs.Mode. */
val fixtureModes = listOf("CONCURRENT", "AFTER")

val generateFixtureTests by tasks.registering {
    description = "Generate one StabsImportRegressionBase subclass per fixture binary"
    val outDir = layout.buildDirectory.dir("generated/sources/fixtureTests/kotlin")
    val dir = fixturesDir.asFile
    // Listing is an input so adding/removing a binary regenerates; the task is cheap either way.
    inputs.property("fixtures", provider { dir.listFiles()?.filter { it.isFile }?.map { it.name }?.sorted().orEmpty() })
    outputs.dir(outDir)
    doLast {
        val root = outDir.get().asFile
        root.deleteRecursively()
        root.resolve("ghistabs/fixtures").mkdirs()
        val names = dir.listFiles()?.filter { it.isFile }?.map { it.name }?.sorted().orEmpty()
        names.forEach { binary ->
            fixtureModes.forEach { mode ->
                val cls = fixtureClassName(binary, mode)
                // ktlint wants the super type inline when it fits the 120-col limit and wrapped when
                // it doesn't, so pick per class. Built line-by-line rather than with a trimIndent
                // template, whose common-indent stripping mangles the pre-indented wrapped form.
                val args = """("$binary", Mode.$mode)"""
                val oneLine = "class $cls : StabsImportRegressionBase$args"
                val decl =
                    if (oneLine.length <= 120) oneLine else "class $cls :\n    StabsImportRegressionBase$args"
                root.resolve("ghistabs/fixtures/$cls.kt").writeText(
                    listOf(
                        "// GENERATED by :generateFixtureTests from src/test/resources/binaries — do not edit.",
                        "package ghistabs.fixtures",
                        "",
                        "import ghistabs.Mode",
                        "import ghistabs.StabsImportRegressionBase",
                        "",
                        decl,
                    ).joinToString("\n", postfix = "\n"),
                )
            }
        }
        logger.lifecycle("generateFixtureTests: ${names.size * fixtureModes.size} fixture classes")
    }
}

kotlin.sourceSets["test"].kotlin.srcDir(generateFixtureTests)

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
    // One class per fixture (see generateFixtureTests) means forks now distribute real work.
    // RAM-bound, not CPU-bound: each invocation measured ~1.7GB RSS / ~170% CPU, so 4 forks is
    // ~7GB and ~7 cores of a 16-core/30GB box. -PmaxForks=1 for perf measurement — parallel forks
    // add timing jitter (±16% vs ±4.5% isolated), enough to fake a 20-30% regression.
    maxParallelForks = (providers.gradleProperty("maxForks").orNull?.toIntOrNull() ?: 4).coerceAtLeast(1)
    maxHeapSize = "2g"
    // -Pfixture=<exact filename>[,…] narrows two ways: the system property still gates the base
    // class (skips a stray invocation), and the gradle filter drops the generated classes outright
    // so unselected fixtures never boot a JVM at all.
    systemProperty("fixtureFilter", providers.gradleProperty("fixture").getOrElse(""))
    // Both filters select generated classes: -Pfixture=<file>[,…] and/or -Pmode=CONCURRENT|AFTER.
    // Their intersection is what runs, so unselected combinations never boot a JVM.
    val wantFixtures = providers.gradleProperty("fixture").orNull.orEmpty()
        .split(',').map { it.trim() }.filter { it.isNotEmpty() }
    val wantModes = providers.gradleProperty("mode").orNull.orEmpty()
        .split(',').map { it.trim().uppercase() }.filter { it.isNotEmpty() }.ifEmpty { fixtureModes }
    if (wantFixtures.isNotEmpty() || wantModes != fixtureModes) {
        filter {
            val binaries = wantFixtures.ifEmpty {
                fixturesDir.asFile.listFiles()?.filter { it.isFile }?.map { it.name }.orEmpty()
            }
            binaries.forEach { b ->
                wantModes.forEach { m -> includeTestsMatching("ghistabs.fixtures.${fixtureClassName(b, m)}") }
            }
            isFailOnNoMatchingTests = false
        }
    }
    // -Pmode=CONCURRENT|AFTER narrows the analyzer execution mode similarly (blank = both).
    systemProperty("modeFilter", providers.gradleProperty("mode").getOrElse(""))
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
    // -Pjfr[=<file>]: record a JFR profile from JVM start (captures load + autoanalysis + import),
    // dumped on exit. Defaults under build/test-output/jfr/; `%p` keeps forks distinct if ever >1.
    // Analyse with the jdk.jfr.consumer RecordingFile API, NOT `jfr print`/`jfr view` — both die with
    // StringIndexOutOfBoundsException in ValueFormatter.formatMethod on Kotlin synthetic frames.
    providers.gradleProperty("jfr").orNull?.let { jfr ->
        val path = jfr.ifBlank { "${layout.buildDirectory.get().asFile}/test-output/jfr/$reportName-%p.jfr" }
        // JFR won't create missing directories — it aborts JVM startup instead ("Could not start
        // recording, not able to write to file"), taking the whole test run with it.
        file(path).parentFile?.mkdirs()
        jvmArgs("-XX:StartFlightRecording=settings=profile,dumponexit=true,maxsize=500m,filename=$path")
    }
}

val integrationTest = tasks.register<Test>("integrationTest") {
    description = "Real-binary assertion tests against binary fixtures (@Tag(\"integration\"))"
    useJUnitPlatform { includeTags("integration") }
    headlessGhidraConfig("integrationTest")
}

// Diagnostic generators (degradation dumps, source skeletons, type probes) — @Tag("probe"), split
// out of `integrationTest` so they don't run in CI. Run on demand, narrow with -Pfixture=<name>.
val probeDump = tasks.register<Test>("probeDump") {
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

apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")

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
val cliJvmArgs = listOf(
    "-Xmx2g",
    "-Djava.awt.headless=true",
    "-Dfile.encoding=UTF8",
    "-Duser.country=US",
    "-Duser.language=en",
    "--enable-native-access=ALL-UNNAMED",
    "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.awt=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
)

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
                    appendLine($$"  ghistabs.cli.MainKt \"$@\"")
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
