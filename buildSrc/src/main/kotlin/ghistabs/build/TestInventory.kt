package ghistabs.build

import org.gradle.api.Project
import java.io.File

private val CLASS_RE = Regex("""(?m)^(?:internal |abstract )?class (\w+)""")
private val PACKAGE_RE = Regex("""(?m)^package ([\w.]+)""")
private val TAG_RE = Regex("""@Tag\("(\w+)"\)""")
private val TEST_RE = Regex("""@(?:Test|ParameterizedTest|ParameterizedClass)\b""")

/**
 * List test classes grouped by JUnit tag. Reads the sources rather than the compiled classes so it
 * costs nothing to run and works before a build; the cost is that it sees `@Tag` textually, so a tag
 * applied any way other than a literal annotation is invisible to it.
 */
fun Project.registerTestInventory(testRoot: File) = tasks.register("listTests") {
    group = "verification"
    description = "List test classes grouped by tag (unit/integration/probe)"
    val projectDir = projectDir
    doLast {
        val byTag = sortedMapOf<String, MutableList<String>>()
        testRoot.walkTopDown().filter { it.extension == "kt" }.forEach { f ->
            val text = f.readText()
            if (!TEST_RE.containsMatchIn(text)) return@forEach // skip helpers with no test methods
            val cls = CLASS_RE.find(text)?.groupValues?.get(1) ?: return@forEach
            val pkg = PACKAGE_RE.find(text)?.groupValues?.get(1).orEmpty()
            val tag = TAG_RE.find(text)?.groupValues?.get(1) ?: "unit"
            val methods = TEST_RE.findAll(text).count()
            byTag.getOrPut(tag) { mutableListOf() }.add("  $pkg.$cls  ($methods tests)  ${f.relativeTo(projectDir)}")
        }
        byTag.forEach { (tag, rows) ->
            logger.lifecycle("\n$tag (${rows.size}):")
            rows.sorted().forEach(logger::lifecycle)
        }
        logger.lifecycle("\nRun: ./gradlew test | integrationTest [-Pfixture=<name>] | probeDump")
    }
}
