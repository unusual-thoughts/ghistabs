plugins {
    id("org.jetbrains.kotlin.jvm") version "2.3.21"
}

dependencies {
    implementation(kotlin("stdlib"))
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
}

val ghidraInstallDir =
    System.getenv("GHIDRA_INSTALL_DIR") ?: project.properties["GHIDRA_INSTALL_DIR"]?.toString() ?: "/opt/ghidra"

apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")

tasks.register("distributeExtension") {
    group = "Ghidra"
//    apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")
    dependsOn(":buildExtension")
}

// Exclude additional files from the built extension
// Ex: buildExtension.exclude(".idea/**")
