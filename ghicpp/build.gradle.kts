import ghistabs.build.ghidraInstallDir
import ghistabs.build.registerHeadlessTest

// The C++ extension: the class passes, the ABI readers, the gcc/MinGW fix-ups and the Class Hierarchy
// window, on any binary. It knows nothing of stabs; ghistabs bundles it.
plugins {
    id("ghidra-module")
    id("ghidra-extension")
}

dependencies {
    api(project(":ghidrakt"))
    testImplementation(testFixtures(project(":ghidrakt")))
    testImplementation(libs.bundles.junit) // jupiter + junit4, the latter for Ghidra's test harness
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.kotlinx.serialization.json)
    // AbstractGhidraHeadlessIntegrationTest and its harness, from the standard install paths.
    testImplementation(fileTree(ghidraInstallDir.resolve("Ghidra/Features/Base/lib")) { include("Base.jar") })
    testImplementation(fileTree(ghidraInstallDir.resolve("Ghidra/Test")) { include("**/lib/*.jar") })
}

// The STL archives ship in data/typeinfo/msvc, where Ghidra lists them, and in the jar for builds that
// bundle only the jar (MsvcStlArchives falls back to those).
tasks.processResources {
    from("data/typeinfo/msvc") { into("ghicpp/stl") }
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
}

registerHeadlessTest(
    "integrationTest",
    "ghicpp's tests against binary fixtures (@Tag(\"integration\"))",
    tag = "integration",
) {
    // -Pregression narrows the run to ghistabs' generated fixture matrix, as before the split.
    val regression = providers.gradleProperty("regression")
    onlyIf("not a -Pregression run") { !regression.isPresent }
}

registerHeadlessTest(
    "probes",
    "Run ghicpp's @Tag(\"probe\") diagnostic dumps (not part of integrationTest)",
    tag = "probe",
)
