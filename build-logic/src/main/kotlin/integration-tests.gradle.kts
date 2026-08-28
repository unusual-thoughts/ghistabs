import ghistabs.build.registerHeadlessTest
import ghistabs.build.sourceSets

// Run the integration tests per binary × mode
registerHeadlessTest(
    "integrationTest",
    "Real-binary assertion tests against binary fixtures (@Tag(\"integration\"))",
    tag = "integration",
    narrowGeneratedClasses = true,
) { finalizedBy(auditTests) }

// Imports a real fixture against exactly what we ship: serializers get reached from class
// initializers, so a missing `-json` fails in the GUI while every ordinary test passes.
registerHeadlessTest(
    "noSerializationTest",
    "Import a fixture with kotlinx-serialization-json off the classpath (guards `compileOnly`)",
    tag = "integration",
) {
    classpath = classpath.filter { !it.name.startsWith("kotlinx-serialization-json") }
    filter { includeTestsMatching("ghistabs.integration.AoutStabsIntegrationTest") }
}

// Own task, not `integrationTest --tests`: Gradle ANDs that with the generated-class filter, which
// selects nothing and still reports SUCCESS.
registerHeadlessTest(
    "noReturnTest",
    "Non-returning roster for one fixture (-Pfixture=<file>; add -PdisableAnalyzers=reachability for before)",
    tag = "integration",
) { filter { includeTestsMatching("ghistabs.NoReturnFixtureIntegrationTest") } }

// Diagnostic generators, split out of integrationTest so they don't run in CI.
registerHeadlessTest(
    "probes",
    "Run @Tag(\"probe\") diagnostic dumps (not part of integrationTest)",
    tag = "probe",
)

// Reads the dumps integrationTest wrote, so it must run after it — and needs no headless config.
val auditTests = tasks.register<Test>("auditTests") {
    description = "Corpus-level audits over the dumps integrationTest wrote"
    useJUnitPlatform { includeTags("audit") }
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    outputs.upToDateWhen { false }
    testLogging { events("passed", "skipped", "failed") }
}
