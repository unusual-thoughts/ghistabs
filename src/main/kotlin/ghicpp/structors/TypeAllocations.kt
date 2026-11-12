package ghicpp.structors

import ghicpp.DECOMPILE_TIMEOUT_SECONDS
import ghicpp.classStruct
import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitor.DUMMY
import ghistabs.diagnose.DiagnosticSink
import ghistabs.toClass
import ghistabs.useWith

/**
 * Types the variable each [InlinedConstruction] builds its object in as a pointer to the class it builds: what
 * `operator new` returns, in the function that inlines the constructor, as `RecoverClassesFromRTTIScript` types
 * `this`. A variable whose type a user or the debug info locked stays as it is.
 */
fun Program.typeAllocations(found: FoundStructors, sink: DiagnosticSink, monitor: TaskMonitor = DUMMY): Int {
    var typed = 0
    monitor.initialize(found.inlinedByFunction.size.toLong(), "Typing the objects constructors inlined after new build")
    DecompInterface().useWith(this) { decomp ->
        for ((func, built) in found.inlinedByFunction) {
            if (monitor.isCancelled) break
            monitor.incrementProgress()
            val high = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction ?: continue
            val calls = high.pcodeOps.asSequence().filter { it.opcode == PcodeOp.CALL }.associateBy { it.seqnum.target }
            for (construction in built) {
                val struct = construction.built.ns?.toClass()?.let(::classStruct) ?: continue
                val symbol = calls[construction.at]?.output?.namedVariable()?.symbol ?: continue
                if (symbol.isTypeLocked) continue
                val type = PointerDataType(struct, dataTypeManager)
                if (symbol.dataType.isEquivalent(type)) continue
                runCatching { HighFunctionDBUtil.updateDBVariable(symbol, null, type, SourceType.ANALYSIS) }
                    .onSuccess { typed++ }
                    .onFailure {
                        sink.warn("allocation-untyped", "${func.name} -> ${struct.name} *: $it", construction.at)
                    }
            }
        }
    }
    return typed
}

const val MAX_COPIES = 4

/** The variable [this] lands in: its own, or where the decompiler casts or copies it into a named one. */
private fun Varnode.namedVariable(depth: Int = 0): HighVariable? {
    high?.takeIf { it.symbol != null }?.let { return it }
    if (depth >= MAX_COPIES) return null
    return descendants.asSequence()
        .filter { it.opcode == PcodeOp.CAST || it.opcode == PcodeOp.COPY }
        .firstNotNullOfOrNull { it.output?.namedVariable(depth + 1) }
}
