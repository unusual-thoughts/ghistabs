package ghistabs.diag

import ghistabs.parser.HeaderFile
import ghistabs.parser.SourceFile
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class AttributionTraceDumpTest {
    private fun stdHeader(path: String): SourceFile.HeaderSource = SourceFile.HeaderSource(HeaderFile(path, 0L, null))

    @Test
    fun testFormatForTypeNoMatches() {
        val result = AttributionTraceDump.formatForType("Foo", emptyList())
        assertEquals("Foo not routed to /std/* in this run", result)
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
        assertTrue(result.contains("Bar"))
        assertTrue(result.contains(path))
        assertTrue(result.contains("/std/string"))
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
        assertEquals(2, lines.size)
        assertTrue(lines[0].contains("Baz"))
        assertTrue(lines[1].contains("Baz"))
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
        assertTrue(Files.exists(outFile))
        val content = Files.readString(outFile)
        assertTrue(content.contains("Test"))
        assertTrue(content.contains("/std/string"))
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
        assertTrue(Files.exists(outFile))
        val content = Files.readString(outFile)
        assertEquals("Unrouted not routed to /std/* in this run", content)
    }
}
