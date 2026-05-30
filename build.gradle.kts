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
    testImplementation(fileTree(mapOf("dir" to "$ghidraInstallDirForTests/Ghidra/Features/Base/lib", "include" to "Base.jar")))
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
        description = "Real-binary tests against bouniaf fixtures"
        group = "verification"
        useJUnitPlatform { includeTags("integration") }
        testClassesDirs = sourceSets["test"].output.classesDirs
        classpath = sourceSets["test"].runtimeClasspath
        shouldRunAfter("test")
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
