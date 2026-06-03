package ghistabs.importer

import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.diag.BookmarkSink
import ghistabs.diag.DiagnosticSink
import ghistabs.diag.StabsDiagnostics
import org.jetbrains.annotations.TestOnly

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
    @get:TestOnly val log: Log,
    val monitor: TaskMonitor,
    val options: StabsOptions = StabsOptions(),
) {
    val dtm: DataTypeManager = program.dataTypeManager
    val symtab: SymbolTable = program.symbolTable
    val diagnostics: StabsDiagnostics = StabsDiagnostics()
    val sink: BookmarkSink = BookmarkSink(program, log, diagnostics)
    val resolver: AddressResolver = ProgramAddressResolver(program)
}
