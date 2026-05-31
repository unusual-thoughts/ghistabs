package ghistabs.importer

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.container.AddressResolver
import ghistabs.diag.StabsDiagnostics

data class StabsOptions(
    val createImportedLabels: Boolean = true,
    val applyPlateComments: Boolean = true,
    val applyVtables: Boolean = true,
)

data class PassResult(
    val recordsRead: Int = 0,
    val recordsParsed: Int = 0,
    val parseErrors: Int = 0,
    val typesMaterialised: Int = 0,
    val functionsApplied: Int = 0,
    val globalsApplied: Int = 0,
    val classesApplied: Int = 0,
)

class ImportContext(
    val program: Program,
    val log: MessageLog,
    val monitor: TaskMonitor,
    val options: StabsOptions = StabsOptions(),
) {
    val dtm: DataTypeManager = program.dataTypeManager
    val symtab: SymbolTable = program.symbolTable
    val diagnostics: StabsDiagnostics = StabsDiagnostics()
    val sink: BookmarkSink = BookmarkSink(program, log, diagnostics)
    val resolver: AddressResolver = AddressResolver(program)
}
