package ghistabs.importer

import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.diagnose.BookmarkSink
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
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
)

class ImportContext<Log : DiagnosticSink>(
    val program: Program,
    val monitor: TaskMonitor,
    val options: StabsOptions,
    @get:TestOnly val log: Log,
    val diagnostics: StabsDiagnostics,
) {
    val dtm: DataTypeManager = program.dataTypeManager
    val symtab: SymbolTable = program.symbolTable
    val sink: BookmarkSink = BookmarkSink(program, log, diagnostics)
    val resolver: AddressResolver = ProgramAddressResolver(program)

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
