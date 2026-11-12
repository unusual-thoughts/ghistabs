import ghistabs.build.ghidraInstallDir

// A plain Kotlin library over Ghidra, for the extensions to bundle: it compiles against the install's
// jars, as buildExtension.gradle has an extension do, but ships none of them.
plugins {
    id("ghidra-module")
    `java-library`
}

dependencies {
    val ghidra = fileTree(ghidraInstallDir.resolve("Ghidra")) {
        include("Framework/**/*.jar", "Features/**/*.jar", "Debug/**/*.jar", "Processors/**/*.jar")
    }
    compileOnly(ghidra)
    testImplementation(ghidra)
}
