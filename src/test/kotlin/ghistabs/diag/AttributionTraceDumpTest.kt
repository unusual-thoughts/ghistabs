package ghistabs.diag

import ghistabs.diag.AttributionTrace
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class AttributionTraceDumpTest {
    @Test
    fun testFormatForTypeNoMatches() {
        val traces = emptyList<AttributionTrace>()
        val result = AttributionTraceDump.formatForType("Foo", traces)
        assertEquals("Foo not routed to /std/* in this run", result)
    }

    @Test
    fun testFormatForTypeOneMatch() {
        val traces =
            listOf(
                AttributionTrace(
                    typeName = "Bar",
                    matchedCU = "/usr/include/c++/3.4.4/string",
                    definingCUs = setOf("/usr/include/c++/3.4.4/string"),
                    routedTo = "/std/string",
                ),
            )
        val result = AttributionTraceDump.formatForType("Bar", traces)
        assertTrue(result.contains("Bar | matched=/usr/include/c++/3.4.4/string"))
        assertTrue(result.contains("routedTo=/std/string"))
        assertTrue(result.contains("definingCUs=/usr/include/c++/3.4.4/string"))
    }

    @Test
    fun testFormatForTypeMultipleMatches() {
        val traces =
            listOf(
                AttributionTrace(
                    typeName = "Baz",
                    matchedCU = "/usr/include/c++/3.4.4/string",
                    definingCUs = setOf("/usr/include/c++/3.4.4/string"),
                    routedTo = "/std/string",
                ),
                AttributionTrace(
                    typeName = "Baz",
                    matchedCU = "/usr/include/c++/3.4.4/vector",
                    definingCUs = setOf("/usr/include/c++/3.4.4/vector"),
                    routedTo = "/std/vector",
                ),
            )
        val result = AttributionTraceDump.formatForType("Baz", traces)
        val lines = result.split("\n")
        assertEquals(2, lines.size, "Should have two lines for two matches")
        assertTrue(lines[0].contains("Baz"))
        assertTrue(lines[1].contains("Baz"))
    }

    @Test
    fun testWriteTraceArtifactCreatesDir(
        @TempDir tempDir: Path,
    ) {
        val outDir = tempDir.resolve("deep/nested/path")
        val traces =
            listOf(
                AttributionTrace(
                    typeName = "Test",
                    matchedCU = "/usr/include/c++/3.4.4/string",
                    definingCUs = setOf("/usr/include/c++/3.4.4/string"),
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
        assertTrue(Files.exists(outFile), "Output file should exist")
        val content = Files.readString(outFile)
        assertTrue(content.contains("Test"))
        assertTrue(content.contains("/std/string"))
    }

    @Test
    fun testWriteTraceArtifactEmptyTracesWritesNotRoutedMessage(
        @TempDir tempDir: Path,
    ) {
        val outDir = tempDir.resolve("output")
        val traces = emptyList<AttributionTrace>()
        AttributionTraceDump.writeTraceArtifact(
            typeName = "Unrouted",
            traces = traces,
            outDir = outDir,
            filename = "unrouted-trace.txt",
        )
        val outFile = outDir.resolve("unrouted-trace.txt")
        assertTrue(Files.exists(outFile))
        val content = Files.readString(outFile)
        assertEquals("Unrouted not routed to /std/* in this run", content)
    }
}
