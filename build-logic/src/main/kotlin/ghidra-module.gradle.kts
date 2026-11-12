import ghistabs.build.ghidraAtLeast
import ghistabs.build.ghidraJavaVersion
import ghistabs.build.sourceSets
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

// What every subproject builds with: Kotlin (and its serialization plugin) at Ghidra's Java level, ktlint, detekt and the Ghidra
// compat source sets. The Ghidra classpath comes from buildExtension.gradle for an extension
// (`ghidra-extension`) and from `ghidra-library` for the kernel.
plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jlleitschuh.gradle.ktlint")
    id("dev.detekt")
}

val catalog = versionCatalogs.named("libs")

repositories {
    mavenCentral()
}

configure<KotlinJvmProjectExtension> {
    jvmToolchain(ghidraJavaVersion)
    // Ghidra shares one classpath across installed extensions, so the oldest kotlin-stdlib wins —
    // GhidraJupyterKotlin pins 1.9.23. Binding above it fails at runtime in the GUI only.
    compilerOptions { apiVersion.set(KotlinVersion.KOTLIN_1_9) }
}

ktlint {
    version = catalog.findVersion("ktlint").get().requiredVersion
}

// The baseline freezes the size/complexity findings that predate the config so the rules act as a
// ratchet: new violations fail, the known-big functions don't. Shrink it as those get split; don't
// regenerate it wholesale to bury a new hit (`./gradlew detektBaseline` if you must). One config and
// one baseline for every subproject: its entries are keyed by file name.
detekt {
    buildUponDefaultConfig = true
    config.from(rootProject.files(".detekt.yml"))
    baseline = rootProject.file(".detekt-baseline.xml")
}

// Ghidra backwards-compatibility shims: `src/<set>/kotlin-since<v>` builds against Ghidra <v> and
// later, `kotlin-pre<v>` against anything older.
for (set in listOf("main", "test")) {
    for (variant in projectDir.resolve("src").resolve(set).listFiles().orEmpty().filter {
        when {
            it.name.startsWith("kotlin-since") -> ghidraAtLeast(it.name.substring(12))
            it.name.startsWith("kotlin-pre") -> !ghidraAtLeast(it.name.substring(10))
            else -> false
        }
    }) {
        the<KotlinJvmProjectExtension>().sourceSets.named(set) { kotlin.srcDir(variant) }
        sourceSets.named(set) { java.srcDir(variant) }
    }
}

// Where the binary fixtures are, for TestBinaries: the corpus in the root project, the hello builds in
// ghicpp. Every project's tests read them in place.
tasks.withType<Test>().configureEach {
    systemProperty("binariesDir", rootProject.file("src/test/resources/binaries").path)
    systemProperty("hellosDir", rootProject.file("ghicpp/src/test/resources/binaries/features").path)
}
