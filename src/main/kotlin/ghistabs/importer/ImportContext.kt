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
}

/**
 * Test-only side-channel: a [Program] can have an extra [ImportContext] installed
 * so that when Ghidra invokes [ghistabs.StabsAnalyzer.added] (CONCURRENT mode), the
 * analyzer tees its output to that sink in addition to Ghidra's [MessageLog].
 *
 * Production code does not install anything here; the lookup just returns null
 * and the analyzer logs to MessageLog only.
 */
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
