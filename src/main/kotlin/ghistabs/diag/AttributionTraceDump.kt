package ghistabs.diag

import java.nio.file.Files
import java.nio.file.Path

object AttributionTraceDump {
    /** Format the trace entries for the given typeName. Empty list → single "not routed" line. */
    fun formatForType(
        typeName: String,
        traces: List<AttributionTrace>,
    ): String {
        val matching = traces.filter { it.typeName == typeName }
        if (matching.isEmpty()) return "$typeName not routed to /std/* in this run"
        return matching.joinToString("\n") { t ->
            "${t.typeName} | matched=${t.matchedCU} | routedTo=${t.routedTo} | definingCUs=${t.definingCUs.joinToString(",")}"
        }
    }

    fun writeTraceArtifact(
        typeName: String,
        traces: List<AttributionTrace>,
        outDir: Path,
        filename: String,
    ) {
        Files.createDirectories(outDir)
        Files.writeString(outDir.resolve(filename), formatForType(typeName, traces))
    }
}
