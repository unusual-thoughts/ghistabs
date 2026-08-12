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

data class PassResult(
    val recordsRead: Int,
    val recordsParsed: Int,
    val parseErrors: Int,
    val typesMaterialized: Int,
    val functionsApplied: Int,
    val globalsApplied: Int,
    val classesApplied: Int,
    val constantsApplied: Int,
    val staticMembersApplied: Int,
    /** Zero-length [ghidra.program.model.sourcemap.SourceMapEntry]s the program now holds. */
    val sourceMapEntries: Int,
) {
    companion object {
        /** Nothing ran — the no-stabs path. Spelled out so a new field must be considered here too. */
        val NOTHING = PassResult(
            recordsRead = 0,
            recordsParsed = 0,
            parseErrors = 0,
            typesMaterialized = 0,
            functionsApplied = 0,
            globalsApplied = 0,
            classesApplied = 0,
            constantsApplied = 0,
            staticMembersApplied = 0,
            sourceMapEntries = 0,
        )
    }
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
    val options: StabsOptions,
    @get:TestOnly val terminal: Terminal,
    val diagnostics: StabsDiagnostics,
) : DiagnosticSink by TeeSink(diagnostics, terminal) {
    val dtm: DataTypeManager = program.dataTypeManager
    val symtab: SymbolTable = program.symbolTable
    val resolver: AddressResolver = ProgramAddressResolver(program, this)
}
