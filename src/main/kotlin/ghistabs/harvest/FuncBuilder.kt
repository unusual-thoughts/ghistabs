package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.parse.*

/**
 * A function being accumulated: its record-order params and its block tree
 */
internal class FuncBuilder(val func: Func, sink: DiagnosticSink) {
    val blockBuilder = BlockTreeBuilder(sink)
    val params = mutableListOf<ParamSymbol>()
    val lines = mutableListOf<LineEntry>()
    var sizeBytes: ULong? = null

    /**
     * The function's own file is its entry's. Not the N_SO/N_SOL partition at the entry — measured
     * at 1155 overrides on locale_test, and wrong where it fires (`std::_Destroy` reads
     * stl_construct.h by its lines and `iomanip` by the partition, the label having been planted
     * mid-symbol-flush).
     */
    val Func.source get() = lines.entry?.source ?: origin.cu.identity

    fun toHarvested(): Func = blockBuilder.finish(lines, func.source).let { (locals, blocks) ->
        func.copy(
            origin = func.origin.copy(sourceFile = func.source),
            lineEntries = lines,
            locals = locals,
            params = params.map { it.withSource(func.source) },
            blocks = blocks,
            // gcc 12 and modern ELF emitters omit the empty-name N_FUN end marker and delimit with
            // the outermost N_RBRAC instead. Read here rather than at every context switch: no
            // bracket can join a function once the next one opens.
            sizeBytes = sizeBytes ?: blockBuilder.lastClose?.let { (it.offset - func.addr.offset).toULong() },
        )
    }
}
