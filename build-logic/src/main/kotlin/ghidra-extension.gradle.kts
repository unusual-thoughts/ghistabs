import ghistabs.build.ghidraInstallDir
import ghistabs.build.ghidraUserDir
import java.util.zip.ZipFile
import kotlin.io.path.createDirectories

apply(from = ghidraInstallDir.resolve("support/buildExtension.gradle").toFile())

/** Every subproject's lib/, which buildExtension.gradle fills for an extension. */
val projectLibDirs = rootProject.allprojects.map { it.layout.projectDirectory.dir("lib").asFile }

/** Where every subproject's own jar is built. */
val projectJarDirs = rootProject.allprojects.map { it.layout.buildDirectory.dir("libs").get().asFile }

/**
 * The other subprojects' jars this extension runs on, which it ships in its zip's lib/. Above the tasks
 * that read it: buildExtension.gradle makes its tasks eagerly, so their configure blocks run here.
 */
val bundledJars = configurations.named("runtimeClasspath").map { cfg ->
    val dirs = projectJarDirs.map { it.canonicalPath + File.separator }
    cfg.filter { jar -> dirs.any { jar.canonicalPath.startsWith(it) } }
}

// zipSource assumes a Java layout, differently per version: 10.4 takes all of `src/**/*`, which drags
// the test fixture binaries into the shipped zip, while 11+ takes `src/main/java/`, which doesn't
// exist here — leaving the task NO-SOURCE so no source zip ships at all. Name the Kotlin sources
// instead: `kotlin*` covers the main tree and the `kotlin-pre*`/`kotlin-since*` compat variants.
tasks.named<Zip>("zipSource") {
    includeEmptyDirs = false
    setIncludes(setOf("src/main/kotlin*/**"))
}

// buildExtension zips the whole projectDir, so whitelist the content instead
tasks.named<Zip>("buildExtension") {
    includeEmptyDirs = false
    include(
        "extension.properties",
        "Module.manifest",
        "README.md",
        "lib/**",
        "data/**",
        "ghidra_scripts/**",
        "${project.name}.jar",
        "${project.name}-src.zip",
    )
    // The include filter sees the bundled jars by their own names, before the rename below.
    include(rootProject.allprojects.map { "${it.name}.jar" })
    // In a release, ClassSearcher scans only the jars in a module's lib/ whose name starts with the
    // module's (ClassJar.isModuleDependencyJar, the rule `Base_ext.jar` follows): a bundled `ghicpp.jar`
    // would ship its analyzers and plugin unregistered. So each goes in under this one's name,
    // `ghistabs_ghicpp.jar`.
    val prefix = "${project.name}_"
    from(bundledJars) {
        into("${project.name}/lib")
        rename { prefix + it }
    }
}

/**
 * Unpack the extension zip into Ghidra's user extensions dir, replacing any previous install. Located
 * at execution: an absent user dir should fail this task, not every build.
 */
tasks.register("installExtension") {
    group = "ghidra"
    description = "Build and install the extension into the Ghidra user extensions directory"
    dependsOn("buildExtension")
    val projectName = project.name // not `name`: inside register{} that is the task's own name
    val extensionDir = ghidraUserDir.resolve("Extensions")
    val zip = (tasks.named("buildExtension").get() as Zip).archiveFile
    doLast {
        val targetDir = extensionDir.createDirectories().toFile()
        targetDir.resolve(projectName).takeIf { it.exists() }?.let {
            it.deleteRecursively()
            logger.lifecycle("Removed previous install: $it")
        }
        val archive = zip.get().asFile
        archive.unzipInto(targetDir)
        logger.lifecycle("Installed ${archive.name} → $targetDir")
        logger.lifecycle("Restart Ghidra to load the new build.")
    }
}

private fun File.unzipInto(target: File) = ZipFile(this).use { zf ->
    for (entry in zf.entries().asSequence()) {
        val out = File(target, entry.name)
        if (entry.isDirectory) {
            out.mkdirs()
        } else {
            out.parentFile.mkdirs()
            zf.getInputStream(entry).use { input -> out.outputStream().use(input::copyTo) }
        }
    }
}

/**
 * Populate `lib/` with the jars the extension ships, replacing buildExtension.gradle's copyDependencies
 * — a Copy, so dropped dependencies lingered and kept shipping, and its exclude spec is a Gradle 10
 * error. Filtered by path because that script's `api` holds the Ghidra install *and* lib/, and
 * `implementation` extends `api`: no configuration means "ours".
 */
tasks.register<Sync>("syncExtensionLibs") {
    group = "ghidra"
    description = "Populate lib/ with exactly the dependencies the extension ships"
    val libDir = layout.projectDirectory.dir("lib").asFile
    // Resolved here: a provider lambda closing over the Project can't be configuration-cached. Every
    // project's lib/, not only this one's: a bundled extension's `api` holds its own, whose jars this
    // one's runtimeClasspath already names from the Gradle cache. The subprojects' own jars stay out
    // too: buildExtension's `api` takes lib/, and a copy there would shadow the project on every
    // classpath. The zip gets them from [bundledJars].
    val skip = (listOf(ghidraInstallDir.toFile()) + projectLibDirs + projectJarDirs)
        .map { it.canonicalPath + File.separator }
    from(
        configurations.named("runtimeClasspath").map { cfg ->
            cfg.filter { jar -> skip.none { jar.canonicalPath.startsWith(it) } }
        },
    )
    into(libDir)
    preserve { include("README.txt") } // Ghidra's, not ours
}.also { sync ->
    tasks.named("copyDependencies") { enabled = false }
    tasks.named("compileKotlin") { dependsOn(sync) }
    tasks.named("buildExtension") { dependsOn(sync) }
}
