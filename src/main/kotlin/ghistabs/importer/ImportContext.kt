package ghistabs.importer

import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.diagnose.TeeSink
import org.jetbrains.annotations.TestOnly
import java.util.*

data class PassResult(
    val recordsRead: Int = 0,
    val recordsParsed: Int = 0,
    val parseErrors: Int = 0,
    val typesMaterialised: Int = 0,
    val functionsApplied: Int = 0,
    val globalsApplied: Int = 0,
    val classesApplied: Int = 0,
    val constantsApplied: Int = 0,
)

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
    val options: StabsOptions,
    @get:TestOnly val terminal: Terminal,
    val diagnostics: StabsDiagnostics,
) : DiagnosticSink by TeeSink(diagnostics, terminal) {
    val dtm: DataTypeManager = program.dataTypeManager
    val symtab: SymbolTable = program.symbolTable
    val resolver: AddressResolver = ProgramAddressResolver(this)

    /**
     * Populated at end-of-import so tests can run [DemanglerReplacer] against the same
     * `byCanonicalKey` indices the analyzer used — avoids a second `materialiseAll` that
     * would race `.conflict` artifacts under `@Execution(CONCURRENT)`. Null in production.
     */
    @get:TestOnly
    var typeRegistry: ghistabs.materialize.TypeRegistry? = null
        internal set

    /** Companion to [typeRegistry] for test introspection (canonical-key index, divergent collisions). */
    @get:TestOnly
    var typeResolver: ghistabs.harvest.TypeResolver? = null
        internal set
}

/** Test-only side-channel for [ghistabs.StabsAnalyzer.added] to tee output into [ImportContext.log]. */
object StaticContexts {
    private val map = WeakHashMap<Program, ImportContext<*>>()

    @Synchronized
    fun install(ctx: ImportContext<*>) {
        map[ctx.program] = ctx
    }

    @Synchronized
    fun clear(program: Program) {
        map.remove(program)
    }

    @Synchronized
    fun get(program: Program): ImportContext<*>? = map[program]
}
