import ghistabs.build.Fixtures
import ghistabs.build.GHIDRA_JVM_ARGS
import ghistabs.build.fixtureTestSource
import ghistabs.build.headlessGhidraConfig
import ghistabs.build.registerCliLauncher
import ghistabs.build.registerInstallExtension
import ghistabs.build.registerTestInventory

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktlint)
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation(libs.bundles.junit) // jupiter + junit4, the latter for Ghidra's test harness
    testRuntimeOnly(libs.junit.platform.launcher)
    // Only the CLI and the tests serialize, so `-json` stays off the extension's classpath — one less
    // jar to clash there (see the apiVersion note below). `-core` can't follow: the plugin caches an
    // enum property's serializer in the containing class's `<clinit>`, so without it a plain parse dies
    // in `StabRecord.<clinit>`. `noSerializationTest` guards the line between the two.
    implementation(libs.kotlinx.serialization.core)
    compileOnly(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlinx.serialization.json)
}

// Add Ghidra test JARs for integration tests (AbstractGhidraHeadlessIntegrationTest)
val ghidraInstallDir = System.getenv("GHIDRA_INSTALL_DIR")
    ?: project.findProperty("GHIDRA_INSTALL_DIR")?.toString() ?: "/opt/ghidra"

dependencies {
    testImplementation(
        fileTree(
            mapOf(
                "dir" to "$ghidraInstallDir/Ghidra/Features/Base/lib",
                "include" to "Base.jar",
            ),
        ),
    )
    // Add Ghidra Test JARs for AbstractGhidraHeadlessIntegrationTest.
    // Resolves test harness dependencies from standard Ghidra installation paths.
    testImplementation(
        fileTree(
            mapOf(
                "dir" to "$ghidraInstallDir/Ghidra/Test",
                "include" to listOf("**/lib/*.jar"),
            ),
        ),
    )
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
    // Ghidra puts every installed extension's lib/ on one classpath, so the oldest kotlin-stdlib
    // among them can win over the one we ship. GhidraJupyterKotlin pins kotlinVersion=1.9.23
    // (its gradle.properties, still on main), which is the floor. Binding above it fails only at
    // runtime in the GUI — `sequenceOf(x)` resolved to the 2.x single-arg overload and threw
    // NoSuchMethodError, while every test passed against our own 2.3.21 on the test classpath.
    // apiVersion hides post-1.9 declarations from resolution, so that call goes back to the vararg
    // overload and the compiler also stops emitting coroutine spilling intrinsics 1.9.23 lacks.
    compilerOptions { apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9) }
}

ktlint {
    additionalEditorconfig.set(
        mapOf("ktlint_standard_no-wildcard-imports" to "disabled"),
    )
}

// Don't copy `binaries/` into build/resources/test/. It's a ~21M
// pile of manually-placed test fixtures that integration tests open
// directly via File("src/test/resources/binaries/…"); copying it to the
// classpath just bloats the build dir. (Generated test outputs —
// records, logs, harvest dumps — already live under build/test-output/
// so they aren't a concern here. The extension zip excludes src/**
// regardless, so this filter is purely about build-dir hygiene.)
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

// ── Fixture corpus ───────────────────────────────────────────────────────────────────────────
// The binaries directory is the corpus (IntegrationFixtures.ALL lists it at runtime); gradle
// schedules whole classes onto forks, so one generated class per fixture × mode is what parallelises.
// `.md` is the folder's own README, not a fixture. Naming and -P narrowing live in buildSrc's
// `Fixtures`, which the generator, the task filters and the progress listener all read.
val fixtures = Fixtures(
    binaries = layout.projectDirectory.dir("src/test/resources/binaries").asFile
        .listFiles()?.filter { it.isFile && it.extension != "md" }?.map { it.name }?.sorted().orEmpty(),
    fixtureFilter = providers.gradleProperty("fixture").orNull,
    modeFilter = providers.gradleProperty("mode").orNull,
)

val generateFixtureTests = tasks.register("generateFixtureTests") {
    description = "Generate one StabsImportRegressionBase subclass per fixture binary"
    val outDir = layout.buildDirectory.dir("generated/sources/fixtureTests/kotlin")
    // Listing is an input so adding/removing a binary regenerates; the task is cheap either way.
    inputs.property("fixtures", fixtures.binaries)
    outputs.dir(outDir)
    doLast {
        val pkgDir = outDir.get().asFile.resolve(Fixtures.GENERATED_PACKAGE.replace('.', '/'))
        pkgDir.deleteRecursively()
        pkgDir.mkdirs()
        fixtures.binaries.forEach { binary ->
            fixtures.modes.forEach { mode ->
                pkgDir.resolve("${Fixtures.className(binary, mode)}.kt")
                    .writeText(fixtureTestSource(binary, mode))
            }
        }
        logger.lifecycle("generateFixtureTests: ${fixtures.binaries.size * fixtures.modes.size} fixture classes")
    }
}

kotlin.sourceSets.test { kotlin.srcDir(generateFixtureTests) }

tasks.register<Test>("integrationTest") {
    description = "Real-binary assertion tests against binary fixtures (@Tag(\"integration\"))"
    useJUnitPlatform { includeTags("integration") }
    headlessGhidraConfig("integrationTest", fixtures, narrowGeneratedClasses = true)
    finalizedBy(auditWhitelist)
}

// main declares `-json` compileOnly, betting nothing on the analyzer path serializes. Generated code
// reaches for serializers from class initializers, not just serialize() calls, so losing that bet costs
// a NoClassDefFoundError in the GUI while every test passes — the kotlin-stdlib apiVersion bug again.
// So import a real fixture against exactly what we ship. AoutStabsIntegrationTest drives the full path
// over committed C and C++ fixtures and writes no dumps.
tasks.register<Test>("noSerializationTest") {
    description = "Import a fixture with kotlinx-serialization-json off the classpath (guards `compileOnly`)"
    useJUnitPlatform { includeTags("integration") }
    headlessGhidraConfig("noSerializationTest", fixtures)
    classpath = classpath.filter { !it.name.startsWith("kotlinx-serialization-json") }
    filter { includeTestsMatching("ghistabs.AoutStabsIntegrationTest") }
}

// Diagnostic generators (degradation dumps, source skeletons, type probes) — @Tag("probe"), split
// out of `integrationTest` so they don't run in CI. Run on demand, narrow with -Pfixture=<name>.
// Corpus-level audits (@Tag("audit")) read the per-fixture dumps integrationTest produces, so they
// must run after it — as ordinary integration classes they raced their own inputs and skipped.
val auditWhitelist = tasks.register<Test>("auditWhitelist") {
    description = "Corpus-level audits over the dumps integrationTest wrote"
    useJUnitPlatform { includeTags("audit") }
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    outputs.upToDateWhen { false }
    testLogging { events("passed", "skipped", "failed") }
}

tasks.register<Test>("probeDump") {
    description = "Run @Tag(\"probe\") diagnostic dumps (not part of integrationTest)"
    useJUnitPlatform { includeTags("probe") }
    headlessGhidraConfig("probeDump", fixtures)
}

// One fixture × one analyzer setting per invocation — a full load+autoanalysis each — writing a roster
// per setting; `diff`ing the two is the with/without comparison. Its own task because `integrationTest`
// narrows generated classes and Gradle ANDs that with `--tests`, which would select nothing at all and
// still report SUCCESS.
tasks.register<Test>("noReturnTest") {
    description =
        "Non-returning roster for one fixture (-Pfixture=<file>; add -PdisableAnalyzers=reachability for before)"
    useJUnitPlatform { includeTags("integration") }
    headlessGhidraConfig("noReturnTest", fixtures)
    filter { includeTestsMatching("ghistabs.NoReturnFixtureIntegrationTest") }
}

// List every test class grouped by its tag (unit / integration / probe) with its package + file, so
// tests are discoverable even though integration/probe tests are co-located in their SUT's package
// rather than a dedicated folder. Source scan — no compile/boot needed.
registerTestInventory(layout.projectDirectory.dir("src/test/kotlin").asFile)

apply(from = File(ghidraInstallDir).resolve("support/buildExtension.gradle"))

// The freestanding headless CLI lives in its own `cli` source set so neither it nor its clikt
// dependency land on the main runtimeClasspath — buildExtension's copyDependencies would otherwise
// bundle clikt into the extension zip's lib/. `cliImplementation` inherits main's deps (`api` carries
// the Ghidra jars) plus the main output, clikt and the serialization libs. The JSON dumps
// (`ghistabs.diagnose.Dumps`) live here for the same reason; the tests read them off the cli output.
val cli = sourceSets.create("cli")
configurations["cliImplementation"].extendsFrom(configurations["api"], configurations["implementation"])

// Friend the cli compilation to main so it sees main's `internal` API (Harvester.harvest etc.) —
// the same association the test compilation gets automatically.
kotlin.target.compilations.named("cli") {
    associateWith(kotlin.target.compilations.getByName("main"))
}

dependencies {
    "cliImplementation"(sourceSets["main"].output)
    "cliImplementation"(libs.clikt)
    "cliImplementation"(libs.kotlinx.serialization.json)
    testImplementation(sourceSets["cli"].output)
}

// We boot Ghidra from a flat classpath rather than via `ghidra.Ghidra`/GhidraClassLoader, so — like the
// headless test harness — we need the java.base concurrency add-opens under JDK 21. Unlike that harness
// we DON'T set `-Djdk.serialFilterFactory`: HeadlessGhidraApplicationConfiguration installs the Ghidra
// factory programmatically (the test harness only sets the -D because its own serialization runs before
// init), and setting both throws "filter factory already instantiated".
val cliJvmArgs = GHIDRA_JVM_ARGS + listOf("-Xmx2g", "--enable-native-access=ALL-UNNAMED")

// Run the CLI in-process against the `cli` runtime classpath (Ghidra jars + main output + clikt).
// Pass args with `-Pargs="skeleton <binary> -d out"`.
tasks.register<JavaExec>("runCli") {
    group = "application"
    description = "Run the headless skeleton/decomp CLI (ghistabs.cli.MainKt)"
    dependsOn(cli.classesTaskName)
    classpath = cli.runtimeClasspath
    mainClass.set("ghistabs.cli.MainKt")
    jvmArgs(cliJvmArgs)
    args = providers.gradleProperty("args").getOrElse("").split(" ").filter { it.isNotEmpty() }
}

// The CLI's own code (main + cli output) as a single jar, for the standalone launcher's lib dir.
val cliJar = tasks.register<Jar>("cliJar") {
    description = "Generate the JAR for headless skeleton/decomp CLI"
    archiveBaseName.set("ghidra-stabs-cli")
    from(sourceSets["main"].output, sourceSets["cli"].output)
}

registerCliLauncher(cli, cliJar.flatMap { it.archiveFile }, ghidraInstallDir, cliJvmArgs)

registerInstallExtension(
    zip = (tasks.named("buildExtension").get() as Zip).archiveFile,
    distroPrefix = project.extra["DISTRO_PREFIX"].toString(),
    releaseName = project.extra["RELEASE_NAME"].toString(),
)

// Replaces buildExtension.gradle's copyDependencies, which is a Copy, not a Sync — and since that
// script also puts `lib/*.jar` back on the `api` configuration, a dropped dependency lingered there,
// kept itself on both classpaths and kept shipping in the zip. Its exclude spec is also a hard error in
// Gradle 10 (`Task.project` at execution time), and it ordered only compileJava, so compileKotlin raced
// an emptied lib/.
val syncExtensionLibs = tasks.register<Sync>("syncExtensionLibs") {
    group = "ghidra"
    description = "Populate lib/ with exactly the dependencies the extension ships"
    val libDir = layout.projectDirectory.dir("lib").asFile
    // Subtracting by path because there's no configuration that means "ours": that script's `api`
    // fileTrees hold both the Ghidra install and lib/ itself, and `implementation` extends `api`.
    // Prefixes rather than the script's own vals — a provider lambda closing over those captures the
    // script object, which the configuration cache can't serialize.
    val skip = listOf(File(ghidraInstallDir), libDir).map { it.canonicalPath + File.separator }
    from(
        configurations.named("runtimeClasspath").map { cfg ->
            cfg.filter { jar -> skip.none { jar.canonicalPath.startsWith(it) } }
        },
    )
    into(libDir)
    preserve { include("README.txt") } // Ghidra's, not ours
}
tasks.named("copyDependencies") { enabled = false }
tasks.named("compileKotlin") { dependsOn(syncExtensionLibs) }
tasks.named("buildExtension") { dependsOn(syncExtensionLibs) }

// buildExtension zips the whole projectDir, which here is full of uncommitted research corpora, a git
// worktree (prout/), IDE dirs and docs. Rather than exclude that pile, whitelist the actual extension
// content. Patterns are matched relative to each of buildExtension's copy specs, so the top-level tree
// (Module.manifest, lib/, ghidra_scripts/…) is anchored, while the generated jar and source zip — added
// by separate specs straight into lib/ — are matched by their bare filenames.
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
