import ghistabs.build.ghidraInstallDir
import ghistabs.build.sourceSets

// The stabs extension. The C++ extension it bundles is :ghicpp, and the kernel both build on :ghidrakt.
plugins {
    id("ghidra-module")
    id("cli")
    id("test-inventory")
    id("ghidra-extension")
    id("fixture-test-generator")
    id("integration-tests")
}

dependencies {
    implementation(project(":ghicpp"))
    testImplementation(testFixtures(project(":ghidrakt")))
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
