package ghistabs.importer

import ghidra.program.model.listing.Program
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeResolver
import ghistabs.materialize.TypeRegistry
import ghistabs.parse.StabRecord
import org.jetbrains.annotations.TestOnly
import java.util.*

/**
 * Everything a completed stabs import materialized, for post-hoc introspection: the registry/record/
 * harvest dumps, and re-running [ghistabs.importer.DemanglerReplacer] against the analyzer's own
 * `byCanonicalKey` indices. Produced by [StabsImporter]; absent when the program carried no stabs.
 */
data class ImportArtifacts(
    val typeRegistry: TypeRegistry,
    val typeResolver: TypeResolver,
    val harvest: Harvest,
    val records: List<StabRecord>,
)

/**
 * Test↔analyzer rendezvous under `@Execution(CONCURRENT)`. The analyzer owns its own [ImportContext]
 * (it builds the Bookmark/MessageLog terminal), so a test that wants to read what the analyzer produced
 * pre-installs a probe: the analyzer emits into [diagnostics]/[terminal] and hands back [artifacts].
 */
class ImportProbe(val diagnostics: StabsDiagnostics, val terminal: DiagnosticSink) {
    @get:TestOnly
    var artifacts: ImportArtifacts? = null
        internal set

    companion object {
        private val map = WeakHashMap<Program, ImportProbe>()

        @Synchronized
        fun install(ctx: ImportContext<*>): ImportProbe =
            ImportProbe(ctx.diagnostics, ctx.terminal).also { map[ctx.program] = it }

        @Synchronized
        fun clear(program: Program) {
            map.remove(program)
        }

        @Synchronized
        internal fun get(program: Program): ImportProbe? = map[program]
    }
}
