package ghistabs.diagnose

import ghidra.program.model.listing.Program
import org.jetbrains.annotations.TestOnly
import java.util.*

/**
 * Test↔analyzer rendezvous under `@Execution(CONCURRENT)`. An analyzer builds its own sink (the
 * Bookmark/MessageLog terminal), so a test that wants to read what the analyzers reported pre-installs a
 * probe on the program, and each analyzer reports into its [diagnostics] and [terminal] too ([sinkFor]).
 * The stabs import's own probe adds what it materialized ([ghistabs.importer.ImportProbe]).
 */
open class AnalysisProbe(val diagnostics: StabsDiagnostics, val terminal: DiagnosticSink) {
    companion object {
        private val map = WeakHashMap<Program, AnalysisProbe>()

        @Synchronized
        @TestOnly
        fun <P : AnalysisProbe> install(program: Program, probe: P): P = probe.also { map[program] = it }

        @Synchronized
        @TestOnly
        fun clear(program: Program) {
            map.remove(program)
        }

        @Synchronized
        fun get(program: Program): AnalysisProbe? = map[program]

        /**
         * [sink], tee'd onto the probe a test installed on [program], if any: an analyzer reports into the
         * same counters and log the test reads.
         */
        fun sinkFor(program: Program, sink: DiagnosticSink): DiagnosticSink =
            get(program)?.let { TeeSink(sink, it.diagnostics, it.terminal) } ?: sink
    }
}
