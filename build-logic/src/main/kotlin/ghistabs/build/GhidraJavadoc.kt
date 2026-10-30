package ghistabs.build

import java.nio.file.Path
import java.util.zip.ZipFile
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.invariantSeparatorsPathString
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.name
import kotlin.io.path.outputStream
import kotlin.io.path.readLines
import kotlin.io.path.relativeTo
import kotlin.io.path.walk
import kotlin.io.path.writeLines
import kotlin.io.path.writeText

/**
 * Javadoc for every module of a Ghidra install, off the `*-src.zip` each ships beside its jar, rather
 * than only the modules Ghidra's own `createJavadocs` takes in: those whose `build.gradle` applies
 * `gradle/javadoc.gradle`. The pages the install's own `docs/GhidraAPI_javadoc.zip` lacks are marked
 * unofficial ([unofficialPages]).
 */
object GhidraJavadoc {
    /** The JDK-only packages a few of Ghidra's GUI classes reach into. */
    val ADD_EXPORTS = listOf("java.desktop/sun.awt=ALL-UNNAMED", "java.desktop/sun.swing=ALL-UNNAMED")

    /** The stylesheets and scripts, from this build's resources, javadoc adds to every page. */
    val STYLESHEETS = listOf("dark.css", "unofficial.css")
    const val PAGES_SCRIPT = "unofficial-pages.js"
    val SCRIPTS = listOf(PAGES_SCRIPT, "unofficial.js")

    /** Each source zip's module, as its path under `Ghidra/` names it: `Features/MicrosoftCodeAnalyzer`. */
    fun sourceZips(install: Path): Map<Path, String> {
        val ghidra = install.resolve("Ghidra")
        return ghidra.walk().filter { it.name.endsWith("-src.zip") }.sorted()
            .associateWith { it.parent.parent.relativeTo(ghidra).invariantSeparatorsPathString }
    }

    /**
     * Every `.java` in [install]'s source zips into [into], and each one's module into [modules] as
     * `path<TAB>module` lines. `module-info.java` is left out: the sources are documented unnamed.
     */
    fun extract(install: Path, into: Path, modules: Path) {
        val lines = mutableListOf<String>()
        for ((zip, module) in sourceZips(install)) {
            ZipFile(zip.toFile()).use { z ->
                for (entry in z.entries()) {
                    if (entry.isDirectory || !entry.name.endsWith(".java") || entry.name.endsWith("module-info.java")) {
                        continue
                    }
                    val to = into.resolve(entry.name).normalize()
                    require(to.startsWith(into)) { "${entry.name} in $zip escapes $into" }
                    to.parent.createDirectories()
                    z.getInputStream(entry).use { input -> to.outputStream().use(input::copyTo) }
                    lines += "${entry.name}\t$module"
                }
            }
        }
        modules.writeLines(lines)
    }

    /** The page paths, from the doc root, of [zip]'s `api/` javadoc: Ghidra's published API. */
    fun officialPages(zip: Path): Set<String> = ZipFile(zip.toFile()).use { z ->
        z.entries().asSequence().map { it.name }
            .filter { it.startsWith("api/") && it.endsWith(".html") }
            .mapTo(mutableSetOf()) { it.removePrefix("api/") }
    }

    /**
     * The source file a class or package page documents, by the page's path from the doc root:
     * `a/b/Outer.Inner.html` is `a/b/Outer.java`, and a `package-summary.html` its directory. Null
     * for any other page: the indexes, trees and uses.
     */
    fun sourceOf(page: String): String? {
        val dir = page.substringBeforeLast('/', "")
        val name = page.substringAfterLast('/').removeSuffix(".html")
        return when {
            dir.isEmpty() || "/class-use" in "/$dir" || "/doc-files" in "/$dir" -> null
            name == "package-summary" -> "$dir/"
            name == "package-tree" || name == "package-use" -> null
            else -> "$dir/${name.substringBefore('.')}.java"
        }
    }

    /**
     * The class and package pages under [api] that [official] lacks, each to its module off [modules]
     * (several, for a package split across modules), keyed as `unofficial.js` looks them up: the
     * path from the doc root without `.html`.
     */
    fun unofficialPages(api: Path, official: Set<String>, modules: Map<String, String>): Map<String, String> {
        val byDir = modules.entries.groupBy({ it.key.substringBeforeLast('/') + "/" }, { it.value })
        return api.walk().filter { it.isRegularFile() && it.name.endsWith(".html") }
            .map { it.relativeTo(api).invariantSeparatorsPathString }
            .filter { it !in official }
            .mapNotNull { page ->
                val source = sourceOf(page) ?: return@mapNotNull null
                val module = if (source.endsWith(
                        "/",
                    )
                ) {
                    byDir[source]?.distinct()?.sorted()?.joinToString(", ")
                } else {
                    modules[source]
                }
                module?.let { page.removeSuffix(".html") to it }
            }
            .toMap(sortedMapOf())
    }

    /** [pages] as the `window.ghidraUnofficial` [PAGES_SCRIPT] defines, each module named once. */
    fun pagesScript(pages: Map<String, String>): String {
        val modules = pages.values.distinct().sorted()
        val index = modules.withIndex().associate { (i, m) -> m to i }
        return buildString {
            append("window.ghidraUnofficial = {\n  \"modules\": [")
            modules.joinTo(this, ", ") { json(it) }
            append("],\n  \"pages\": {\n")
            pages.entries.joinTo(this, ",\n") { (page, module) -> "    ${json(page)}: ${index.getValue(module)}" }
            append("\n  }\n};\n")
        }
    }

    /** After javadoc ran: the real [PAGES_SCRIPT] over the stand-in it copied. */
    fun markUnofficial(api: Path, officialZip: Path, modules: Path) {
        val official = if (officialZip.exists()) officialPages(officialZip) else emptySet()
        val byFile = modules.readLines().associate { it.substringBefore('\t') to it.substringAfter('\t') }
        val scripts = api.resolve("script-files").takeIf { it.isDirectory() } ?: api
        scripts.resolve(PAGES_SCRIPT).writeText(pagesScript(unofficialPages(api, official, byFile)))
    }

    private fun json(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
