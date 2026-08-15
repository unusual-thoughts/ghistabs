package ghistabs.importer

import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.ImportOptions
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.diagnose.TeeSink
import ghistabs.harvest.Harvest
import ghistabs.harvest.HarvestIndex
import ghistabs.materialize.DataTypeRegistry
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import org.jetbrains.annotations.TestOnly
import java.util.*

data class ImportResult(
    val parsed: ParseResults = ParseResults(),
    val types: TypeResults = TypeResults(),
    val applied: ApplyResults = ApplyResults(),
    /** Zero-length [ghidra.program.model.sourcemap.SourceMapEntry]s the program now holds. */
    val sourceMapEntries: Int = 0,
    /** What the import materialized; null when nothing ran — no stabs, or already imported. */
    val artifacts: ImportArtifacts? = null,
) {
    // Counters only: this is what the analyzer logs, and the artifacts are the whole registry,
    // harvest and record list.
    override fun toString() =
        "ImportResult(parsed=$parsed, types=$types, applied=$applied, sourceMapEntries=$sourceMapEntries)"

    data class ParseResults(val records: Int = 0, val parsed: Int = 0, val errors: Int = 0) {
        constructor(stabs: StabReader.Result, parseErrors: Int) : this(
            records = stabs.totalRecordCount,
            parsed = stabs.records.size - parseErrors,
            errors = parseErrors,
        )
    }

    data class ApplyResults(
        val functions: Int = 0,
        val globals: Int = 0,
        val classes: Int = 0,
        val constants: Int = 0,
        val staticMembers: Int = 0,
    )

    data class TypeResults(val harvested: Int = 0, val materialized: Int = 0)
}

/**
 * The import's shared state, and itself the [DiagnosticSink] everything logs to: each log fans out
 * (unfiltered) to the [diagnostics] accumulator that counts + files it, and to the [terminal]
 * (BookmarkSink+MessageLogSink in prod, CapturingSink in tests) that bookmarks + emits. So there is
 * one place to log (`ctx`/`by ctx`), one to read counters ([diagnostics]), and one @TestOnly handle
 * on the raw terminal ([terminal]).
 */
class ImportContext<Terminal : DiagnosticSink>(
    val program: Program,
    val monitor: TaskMonitor,
    val options: ImportOptions,
    @get:TestOnly val terminal: Terminal,
    val diagnostics: StabsDiagnostics,
) : DiagnosticSink by TeeSink(diagnostics, terminal) {
    val dtm: DataTypeManager = program.dataTypeManager
    val symtab: SymbolTable = program.symbolTable
    val resolver: AddressResolver = program.addressResolver
}

/**
 * Everything a completed stabs import materialized, for post-hoc introspection: the registry/record/
 * harvest dumps, and re-running [ghistabs.importer.DemanglerReplacer] against the analyzer's own
 * `byCanonicalKey` indices. Produced by [StabsImporter]; absent when the program carried no stabs.
 */
data class ImportArtifacts(
    val registry: DataTypeRegistry,
    val index: HarvestIndex,
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
        @TestOnly
        internal fun install(ctx: ImportContext<*>): ImportProbe =
            ImportProbe(ctx.diagnostics, ctx.terminal).also { map[ctx.program] = it }

        @Synchronized
        @TestOnly
        internal fun clear(program: Program) {
            map.remove(program)
        }

        @Synchronized
        internal fun get(program: Program): ImportProbe? = map[program]
    }
}
