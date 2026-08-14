package ghistabs.build

import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.TaskProvider
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult
import org.gradle.kotlin.dsl.get
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.register
import java.util.concurrent.ConcurrentHashMap

/** Every tag the suites are split by. "unit" is the absence of the others, as in `tasks.test`. */
private val TAGS = listOf("unit", "integration", "probe", "audit")

/**
 * List test classes grouped by JUnit tag, via JUnit's own discovery in dry-run mode: everything is
 * discovered and reported, nothing executes.
 *
 * Reading the sources instead would be instant and need no build, but it cannot see a tag that arrives
 * by inheritance — and that is most of this suite. The generated fixture classes carry no annotation of
 * their own; they are integration tests because [StabsImportRegressionBase][Fixtures] is tagged, and
 * they live under build/generated where a src/ scan never looks. A scan also counts abstract bases that
 * never run. Discovery gets all of it right because it is the same discovery the real run performs.
 *
 * One dry run per tag, because a Gradle TestDescriptor carries no tags — the filtering has to happen
 * before the JVM starts. Discovery only reflects over classes, so no Ghidra JVM args are needed.
 */
fun Project.registerTestInventory(): TaskProvider<Task> {
    val testSourceSet = extensions.getByType<JavaPluginExtension>().sourceSets["test"]
    val perTag = TAGS.map { tag ->
        tasks.register<Test>("listTests${tag.replaceFirstChar { it.uppercase() }}") {
            description = "Discover the $tag tests without running them"
            testClassesDirs = testSourceSet.output.classesDirs
            classpath = testSourceSet.runtimeClasspath
            useJUnitPlatform {
                if (tag == "unit") excludeTags(*(TAGS - tag).toTypedArray()) else includeTags(tag)
            }
            systemProperty("junit.platform.execution.dryRun.enabled", "true")
            testLogging { events() } // the listener below is the whole output
            outputs.upToDateWhen { false }
            reportGroupedByClass(tag)
        }
    }
    return tasks.register("listTests") {
        group = "verification"
        description = "List test classes grouped by tag (unit/integration/probe/audit)"
        dependsOn(perTag)
        doLast { logger.lifecycle("\nRun: ./gradlew test | integrationTest [-Pfixture=<name>] | probeDump") }
    }
}

private fun Test.reportGroupedByClass(tag: String) {
    val counts = ConcurrentHashMap<String, Int>()
    addTestListener(object : TestListener {
        override fun beforeSuite(suite: TestDescriptor) {
            suite.className?.let { counts.putIfAbsent(it, 0) }
        }

        override fun beforeTest(testDescriptor: TestDescriptor) = Unit

        override fun afterTest(d: TestDescriptor, result: TestResult) {
            d.className?.let { counts.merge(it, 1, Int::plus) }
        }

        override fun afterSuite(suite: TestDescriptor, result: TestResult) {
            if (suite.parent != null) return
            // A @ParameterizedTest registers its invocations while executing, and a dry run never
            // executes — so those classes are discovered with no test events behind them.
            val parameterized = counts.count { it.value == 0 }
            val total = counts.values.sum().let { if (parameterized == 0) plural(it, "test") else "$it+ tests" }
            logger.lifecycle("\n$tag (${plural(counts.size, "class", "classes")}, $total):")
            counts.toSortedMap().forEach { (cls, n) ->
                logger.lifecycle("  $cls  (${if (n > 0) plural(n, "test") else "parameterized"})")
            }
        }
    })
}

private fun plural(n: Int, one: String, many: String = one + "s") = "$n ${if (n == 1) one else many}"
