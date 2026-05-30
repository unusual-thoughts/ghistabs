plugins {
    id("org.jetbrains.kotlin.jvm") version "2.3.21"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
    testImplementation("org.mockito:mockito-core:5.14.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform { excludeTags("integration") }
    testLogging {
        events("passed", "skipped", "failed")
    }
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
