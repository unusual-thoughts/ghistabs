import ghistabs.build.ghidraAtLeast
import ghistabs.build.ghidraInstallDir
import ghistabs.build.ghidraJavaVersion
import ghistabs.build.sourceSets
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
    id("cli")
    id("test-inventory")
    id("ghidra-extension")
    id("fixture-test-generator")
    id("integration-tests")
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation(libs.bundles.junit) // jupiter + junit4, the latter for Ghidra's test harness
    testRuntimeOnly(libs.junit.platform.launcher)
    // Only the CLI and tests serialize, so `-json` isn't shipped. `-core` must be: the plugin caches
    // an enum property's serializer in the containing class's `<clinit>`. Guarded by noSerializationTest.
    implementation(libs.kotlinx.serialization.core)
    compileOnly(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlinx.serialization.json)
    // AbstractGhidraHeadlessIntegrationTest and its harness, from the standard install paths.
    testImplementation(fileTree(ghidraInstallDir.resolve("Ghidra/Features/Base/lib")) { include("Base.jar") })
    testImplementation(fileTree(ghidraInstallDir.resolve("Ghidra/Test")) { include("**/lib/*.jar") })
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(ghidraJavaVersion)
    // Ghidra shares one classpath across installed extensions, so the oldest kotlin-stdlib wins —
    // GhidraJupyterKotlin pins 1.9.23. Binding above it fails at runtime in the GUI only.
    compilerOptions { apiVersion.set(KotlinVersion.KOTLIN_1_9) }
}

// The baseline freezes the size/complexity findings that predate the config so the rules act as a
// ratchet: new violations fail, the known-big functions don't. Shrink it as those get split; don't
// regenerate it wholesale to bury a new hit (`./gradlew detektBaseline` if you must).
detekt {
    buildUponDefaultConfig = true
    config.from(files(".detekt.yml"))
    baseline = file(".detekt-baseline.xml")
}

// Don't copy `binaries/` into build/resources/test/.
tasks.processTestResources {
    exclude("binaries/**")
}

tasks.test {
    useJUnitPlatform { excludeTags("integration", "probe", "audit") }
    testLogging {
        events("passed", "skipped", "failed")
    }
    // -PlibstdcxxInclude=<dir> points the scan tests at a libstdc++ checkout
    systemProperty("libstdcxxInclude", providers.gradleProperty("libstdcxxInclude").getOrElse(""))
}

// Generate fixture integration tests code, and add it to the test sourceSet
kotlin.sourceSets.test { kotlin.srcDir(tasks.named("generateFixtureTests")) }

// Ghidra backwards-compatibility shims
for (variant in projectDir.resolve("src").resolve("main").listFiles().orEmpty().filter {
    when {
        it.name.startsWith("kotlin-since") -> ghidraAtLeast(it.name.substring(12))
        it.name.startsWith("kotlin-pre") -> !ghidraAtLeast(it.name.substring(10))
        else -> false
    }
}) {
    kotlin.sourceSets.main { kotlin.srcDir(variant) }
    sourceSets.main { java.srcDir(variant) }
}

// CLI target configuration
val cli = sourceSets.create("cli") {
    configurations[implementationConfigurationName]
        .extendsFrom(configurations["api"], configurations["implementation"])

    dependencies {
        implementationConfigurationName(sourceSets["main"].output)
        implementationConfigurationName(libs.clikt)
        implementationConfigurationName(libs.kotlinx.serialization.json)
        testImplementation(output)
    }
}

// Friends cli to main for its `internal` API
kotlin.target.compilations.named(cli.name) {
    associateWith(kotlin.target.compilations.getByName(SourceSet.MAIN_SOURCE_SET_NAME))
}

// build-logic is a separate build: fan the umbrella tasks out to it so one command covers both.
listOf("ktlintCheck", "ktlintFormat", "test").forEach { name ->
    tasks.named(name) { dependsOn(gradle.includedBuild("build-logic").task(":$name")) }
}
