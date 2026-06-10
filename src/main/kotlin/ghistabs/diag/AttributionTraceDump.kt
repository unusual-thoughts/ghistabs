package ghistabs.diag

import java.nio.file.Files
import java.nio.file.Path

object AttributionTraceDump {
    /**
     * Format the trace entries for the given typeName. Empty list → single
     * "not routed" line. Traces are recorded for every `Attribution.categoryFor`
     * decision that calls `recordAttributionTrace` — currently the `/std/`
     * (stdlib match) and `/headers/` (D2 HeaderSource route) branches.
     */
    fun formatForType(typeName: String, traces: List<AttributionTrace>): String {
        val matching = traces.filter { it.typeName == typeName }
        if (matching.isEmpty()) return "$typeName: no attribution trace recorded in this run"
        return matching.joinToString("\n") {
            "${it.typeName} | matched=${it.matchedCU} | routedTo=${it.routedTo} | definingCUs=${
                it.definingCUs.joinToString(",")
            }"
        }
    }

    fun writeTraceArtifact(typeName: String, traces: List<AttributionTrace>, outDir: Path, filename: String) {
        Files.createDirectories(outDir)
        Files.writeString(outDir.resolve(filename), formatForType(typeName, traces))
    }
}
