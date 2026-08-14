import ghistabs.build.*

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktlint)
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
    jvmToolchain(21)
    // Ghidra shares one classpath across installed extensions, so the oldest kotlin-stdlib wins —
    // GhidraJupyterKotlin pins 1.9.23. Binding above it fails at runtime in the GUI only.
    compilerOptions { apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9) }
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
    // -PlibstdcxxInclude=<dir> points the scan tests at a libstdc++ checkout other than the default
    // (~/git/gcc/libstdc++-v3/include). Absent, those tests skip: the corpus is not vendored.
    systemProperty("libstdcxxInclude", providers.gradleProperty("libstdcxxInclude").getOrElse(""))
}

// Gradle schedules whole classes onto forks, so one generated class per fixture × mode is what
// parallelises the corpus run. filtered by -Pfixture (comma separated) and -Pmode
val fixtures = Fixtures.scan(
    dir = layout.projectDirectory.dir("src/test/resources/binaries").asFile,
    fixtureFilter = providers.gradleProperty("fixture").orNull,
    modeFilter = providers.gradleProperty("mode").orNull,
)

// Generate fixture integration tests code, and add it to the test sourceSet
kotlin.sourceSets.test { kotlin.srcDir(registerFixtureTestGenerator(fixtures)) }

// Run the integration tests per binary × mode
registerHeadlessTest(
    "integrationTest",
    "Real-binary assertion tests against binary fixtures (@Tag(\"integration\"))",
    tag = "integration",
    fixtures,
    narrowGeneratedClasses = true,
) { finalizedBy(auditWhitelist) }

// Imports a real fixture against exactly what we ship: serializers get reached from class
// initializers, so a missing `-json` fails in the GUI while every ordinary test passes.
registerHeadlessTest(
    "noSerializationTest",
    "Import a fixture with kotlinx-serialization-json off the classpath (guards `compileOnly`)",
    tag = "integration",
    fixtures,
) {
    classpath = classpath.filter { !it.name.startsWith("kotlinx-serialization-json") }
    filter { includeTestsMatching("ghistabs.AoutStabsIntegrationTest") }
}

// Diagnostic generators, split out of integrationTest so they don't run in CI.
registerHeadlessTest(
    "probeDump",
    "Run @Tag(\"probe\") diagnostic dumps (not part of integrationTest)",
    tag = "probe",
    fixtures,
)

// Own task, not `integrationTest --tests`: Gradle ANDs that with the generated-class filter, which
// selects nothing and still reports SUCCESS.
registerHeadlessTest(
    "noReturnTest",
    "Non-returning roster for one fixture (-Pfixture=<file>; add -PdisableAnalyzers=reachability for before)",
    tag = "integration",
    fixtures,
) { filter { includeTestsMatching("ghistabs.NoReturnFixtureIntegrationTest") } }

// Reads the dumps integrationTest wrote, so it must run after it — and needs no headless config.
val auditWhitelist = tasks.register<Test>("auditWhitelist") {
    description = "Corpus-level audits over the dumps integrationTest wrote"
    useJUnitPlatform { includeTags("audit") }
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    outputs.upToDateWhen { false }
    testLogging { events("passed", "skipped", "failed") }
}

registerTestInventory()

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

// Our code as one jar, for the standalone launcher's lib/.
val cliJar = tasks.register<Jar>("cliJar") {
    description = "Generate the JAR for headless skeleton/decomp CLI"
    archiveBaseName.set("ghidra-stabs-cli")
    from(sourceSets["main"].output, cli.output)
}

// ./gradlew runCli -Pargs="skeleton <binary> -d out"
registerRunCli()
registerBuildCli(cliJar.flatMap { it.archiveFile })

apply(from = ghidraInstallDir.resolve("support/buildExtension.gradle").toFile())
registerInstallExtension((tasks.named("buildExtension").get() as Zip).archiveFile)
registerExtensionLibs()

// buildExtension zips the whole projectDir, so whitelist the content instead
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
