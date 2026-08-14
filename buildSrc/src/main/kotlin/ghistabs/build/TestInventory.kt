package ghistabs.build

import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.tasks.TaskProvider
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult
import org.gradle.kotlin.dsl.get
import org.gradle.kotlin.dsl.register
import java.util.concurrent.ConcurrentHashMap

/** Every tag the suites are split by. "unit" is the absence of the others, as in `tasks.test`. */
private val TAGS = listOf("unit", "integration", "probe", "audit")

fun Project.registerTagInventory(tag: String) = tasks.register<Test>(
    "listTests${tag.replaceFirstChar { it.uppercase() }}",
) {
    description = "Discover the $tag tests without running them"
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    useJUnitPlatform {
        if (tag == "unit") excludeTags(*(TAGS - tag).toTypedArray()) else includeTags(tag)
    }
    systemProperty("junit.platform.execution.dryRun.enabled", "true")
    testLogging { events() } // the listener below is the whole output
    // Console-only. Also avoids reports named after a test whose display name holds a
    // character the filesystem encoding can't map — `clean` then can't delete them.
    reports {
        html.required.set(false)
        junitXml.required.set(false)
    }
    outputs.upToDateWhen { false }
    reportGroupedByClass(tag)
}

/**
 * List test classes by tag, via JUnit discovery in dry-run mode. Scanning sources instead misses tags
 * inherited from a base class — which is how the generated fixture classes get theirs.
 *
 * One run per tag: a Gradle TestDescriptor carries no tags, so filtering happens before JVM start.
 */
fun Project.registerTestInventory(): TaskProvider<Task> {
    val perTag = TAGS.map(::registerTagInventory) // not inside the register below: no nested registration
    return tasks.register("listTests") {
        group = "verification"
        description = "List test classes grouped by tag (unit/integration/probe/audit)"
        dependsOn(perTag)
        doLast { logger.lifecycle("\nRun: ./gradlew test | integrationTest [-Pfixture=<name>] | probeDump") }
    }
}

private fun Test.reportGroupedByClass(tag: String) = addTestListener(object : TestListener {
    val counts = ConcurrentHashMap<String, Int>()
    override fun beforeSuite(suite: TestDescriptor) {
        suite.className?.let { counts.putIfAbsent(it, 0) }
    }

    override fun beforeTest(testDescriptor: TestDescriptor) = Unit

    override fun afterTest(d: TestDescriptor, result: TestResult) {
        d.className?.let { counts.merge(it, 1, Int::plus) }
    }

    override fun afterSuite(suite: TestDescriptor, result: TestResult) {
        if (suite.parent != null) return
        // @ParameterizedTest registers invocations while executing, so a dry run reports none.
        val parameterized = counts.count { it.value == 0 }
        val total = counts.values.sum().let { if (parameterized == 0) plural(it, "test") else "$it+ tests" }
        logger.lifecycle("\n$tag (${plural(counts.size, "class", "classes")}, $total):")
        counts.toSortedMap().forEach { (cls, n) ->
            logger.lifecycle("  $cls  (${if (n > 0) plural(n, "test") else "parameterized"})")
        }
    }
})

private fun plural(n: Int, one: String, many: String = one + "s") = "$n ${if (n == 1) one else many}"
