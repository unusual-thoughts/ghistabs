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
    useJUnitPlatform { excludeTags("integration") }
    testLogging {
        events("passed", "skipped", "failed")
    }
    // Exclude integration test classes from unit test run to avoid loading
    // AbstractGhidraHeadlessIntegrationTest during classpath scanning
    exclude("**/integration/**")
}

val integrationTest =
    tasks.register<Test>("integrationTest") {
        description = "Real-binary tests against bouniaf fixtures"
        group = "verification"
        useJUnitPlatform { includeTags("integration") }
        testClassesDirs = sourceSets["test"].output.classesDirs
        classpath = sourceSets["test"].runtimeClasspath
        shouldRunAfter("test")
        // JVM args mirror ~/git/ghidra/gradle/javaTestProject.gradle:initTestJVM so Ghidra's
        // HeadlessGhidraApplicationConfiguration boots cleanly under JDK 21.
        //
        // Ghidra's Application bootstrap is idempotent (AbstractGenericTest.initialize
        // skips on second call) so test classes in the same JVM share one Ghidra
        // install. Forking per-class — forkEvery=1 — paid the ~30s Ghidra boot
        // 9 times. Drop forking entirely and parallelise across maxParallelForks
        // JVMs instead: gradle splits the 9 test classes across N concurrent JVMs,
        // each booting Ghidra once and reusing it. Each fork needs a real heap;
        // loading bouniafbouniaf.exe + autoanalysis overflows the gradle default
        // -Xmx512m and crashes the worker with NoSuchFileException on the result
        // binary.
        forkEvery = 0
        maxParallelForks = (Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 4)
        maxHeapSize = "2g"
        // -Pfixture=<name> restricts fixture-parameterised probes to one binary for fast cycles.
        systemProperty("fixtureFilter", providers.gradleProperty("fixture").getOrElse(""))
        // -PregenerateBaselines=true rewrites baseline JSONs from observed counters instead of asserting.
        systemProperty("regenerateBaselines", providers.gradleProperty("regenerateBaselines").getOrElse(""))
        jvmArgs(
            // Ghidra installs its own ObjectInputFilter factory; under JDK 21 it must be
            // declared at JVM startup, otherwise the BuiltinFilterFactory wins the race.
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
