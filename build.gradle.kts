plugins {
    id("org.jetbrains.kotlin.jvm") version "2.3.21"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("junit:junit:4.13.2")
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
        description = "Real-binary tests against ADK fixtures"
        group = "verification"
        useJUnitPlatform { includeTags("integration") }
        testClassesDirs = sourceSets["test"].output.classesDirs
        classpath = sourceSets["test"].runtimeClasspath
        shouldRunAfter("test")
        // JVM args mirror ~/git/ghidra/gradle/javaTestProject.gradle:initTestJVM so Ghidra's
        // HeadlessGhidraApplicationConfiguration boots cleanly under JDK 21.
        forkEvery = 1
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

tasks.register("distributeExtension") {
    group = "Ghidra"
    dependsOn(":buildExtension")
}

// Exclude additional files from the built extension
// Ex: buildExtension.exclude(".idea/**")
