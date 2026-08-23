package ghistabs.diagnose

import ghistabs.parse.HeaderFile
import ghistabs.parse.SourceFile
import ghistabs.test.must
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class AttributionTraceDumpTest {
    private fun stdHeader(path: String): SourceFile.HeaderSource = SourceFile.HeaderSource(HeaderFile(path, 0L, null))

    @Test
    fun testFormatForTypeNoMatches() {
        val result = AttributionTraceDump.formatForType("Foo", emptyList())
        result mustBe "Foo: no attribution trace recorded in this run"
    }

    @Test
    fun testFormatForTypeOneMatch() {
        val path = "/usr/include/c++/3.4.4/string"
        val traces = listOf(
            AttributionTrace(
                typeName = "Bar",
                matchedCU = stdHeader(path),
                definingCUs = setOf(stdHeader(path)),
                routedTo = "/std/string",
            ),
        )
        val result = AttributionTraceDump.formatForType("Bar", traces)
        result.must { contains("Bar") }
        result.must { contains(path) }
        result.must { contains("/std/string") }
    }

    @Test
    fun testFormatForTypeMultipleMatches() {
        val traces = listOf(
            AttributionTrace(
                typeName = "Baz",
                matchedCU = stdHeader("/usr/include/c++/3.4.4/string"),
                definingCUs = setOf(stdHeader("/usr/include/c++/3.4.4/string")),
                routedTo = "/std/string",
            ),
            AttributionTrace(
                typeName = "Baz",
                matchedCU = stdHeader("/usr/include/c++/3.4.4/vector"),
                definingCUs = setOf(stdHeader("/usr/include/c++/3.4.4/vector")),
                routedTo = "/std/vector",
            ),
        )
        val result = AttributionTraceDump.formatForType("Baz", traces)
        val lines = result.split("\n")
        lines.size mustBe 2
        lines[0].must { contains("Baz") }
        lines[1].must { contains("Baz") }
    }

    @Test
    fun testWriteTraceArtifactCreatesDir(@TempDir tempDir: Path) {
        val outDir = tempDir.resolve("deep/nested/path")
        val traces = listOf(
            AttributionTrace(
                typeName = "Test",
                matchedCU = stdHeader("/usr/include/c++/3.4.4/string"),
                definingCUs = setOf(stdHeader("/usr/include/c++/3.4.4/string")),
                routedTo = "/std/string",
            ),
        )
        AttributionTraceDump.writeTraceArtifact(
            typeName = "Test",
            traces = traces,
            outDir = outDir,
            filename = "test-trace.txt",
        )
        val outFile = outDir.resolve("test-trace.txt")
        outFile.toFile().must { exists() }
        val content = Files.readString(outFile)
        content.must { contains("Test") }
        content.must { contains("/std/string") }
    }

    @Test
    fun testWriteTraceArtifactEmptyTracesWritesNotRoutedMessage(@TempDir tempDir: Path) {
        val outDir = tempDir.resolve("output")
        AttributionTraceDump.writeTraceArtifact(
            typeName = "Unrouted",
            traces = emptyList(),
            outDir = outDir,
            filename = "unrouted-trace.txt",
        )
        val outFile = outDir.resolve("unrouted-trace.txt")
        outFile.toFile().must { exists() }
        val content = Files.readString(outFile)
        content mustBe "Unrouted: no attribution trace recorded in this run"
    }
}
