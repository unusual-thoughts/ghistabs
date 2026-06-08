package ghistabs.parser

import ghistabs.diag.DiagnosticSink
import ghistabs.diag.DummySink
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import java.util.*

/**
 * Global registry for header files shared across multiple CUs via BINCL/EXCL.
 * Maintains canonical CU integer mapping to avoid hashCode() collisions.
 */
@Serializable
class HeaderRegistry(@Transient val sink: DiagnosticSink = DummySink) : DiagnosticSink by sink {
    /** (filename, checksum) → HeaderFile for cross-CU BINCL/EXCL sharing. */
    @Transient
    private val globalByFilenameChecksum = mutableMapOf<Pair<String, Long>, HeaderFile>()

    fun getOrInsert(filename: String, checksum: Long, cu: SourceFile.CUSource) =
        globalByFilenameChecksum.getOrPut(filename to checksum) {
            HeaderFile(filename, checksum, originatingCu = cu)
        }

    fun recall(filename: String, checksum: Long): HeaderFile = globalByFilenameChecksum[filename to checksum] ?: run {
        log("forward-excl", "$filename checksum=0x${checksum.toString(16)}")
        HeaderFile(filename, checksum, originatingCu = null)
    }

    /** Clear all registries (for test isolation). */
    fun clear() {
        globalByFilenameChecksum.clear()
    }
}

/**
 * Maintains per-CU file context: file number → header mapping, include stack tracking,
 *
 * BINCL/EINCL/EXCL handling:
 * - beginInclude: N_BINCL, allocates fileNum, registers/retrieves header globally, pushes stack.
 * - endInclude: N_EINCL, pops stack (no fileNum change).
 * - remount: N_EXCL, allocates fileNum for shared header (or placeholder if forward EXCL).
 */
@Serializable
class IncludeContext(
    val cu: SourceFile.CUSource,
    @Transient private val sink: DiagnosticSink = DummySink,
    @Transient val registry: HeaderRegistry = HeaderRegistry(sink),
) : DiagnosticSink by sink {
    private val fileNumToHeader: MutableMap<Int, HeaderFile> = mutableMapOf()

    @Transient
    private val includeStack: ArrayDeque<Int> = ArrayDeque()
    private var nextFileNum: Int = 1

    /**
     * N_BINCL: allocates fileNum, either retrieves the existing HeaderFile from the global registry
     * (if we've seen this (filename, checksum) before) or creates a new one and registers globally.
     * Pushes onto includeStack. Returns fileNum.
     */
    fun beginInclude(filename: String, checksum: Long): Int {
        val fileNum = nextFileNum++
        fileNumToHeader[fileNum] = registry.getOrInsert(filename, checksum, cu)
        includeStack.push(fileNum)
        return fileNum
    }

    /**
     * N_EINCL: pops the include stack. No fileNum change.
     * Logs a warning if stack is empty (unbalanced N_EINCL).
     */
    fun endInclude() {
        if (includeStack.isNotEmpty()) {
            includeStack.pop()
        } else {
            log("einc-unbalanced", "endInclude with empty stack")
        }
    }

    val currentInclude get() = includeStack.lastOrNull()?.let { fileNumToHeader[it] }

    /**
     * N_EXCL: allocates fileNum for a header that was previously INCLUDed (or will be later, in the case
     * of a forward EXCL). If the (filename, checksum) is already known globally, reuses it. Otherwise,
     * allocates a placeholder header with originatingCu = "<unknown>". Does NOT push includeStack.
     * The placeholder is registered ONLY in the local fileNumToHeader, NOT in the global registry,
     * so a later real BINCL gets its own slot and the forward-EXCL CU's types diverge from it.
     * Returns fileNum.
     */
    fun remount(filename: String, checksum: Long): Int {
        val fileNum = nextFileNum++
        fileNumToHeader[fileNum] = registry.recall(filename, checksum)
        return fileNum
    }

    /**
     * Lookup header for a given fileNum.
     */
    internal fun headerForFileNum(fileNum: Int): HeaderFile? = fileNumToHeader[fileNum]

    fun sourceFor(id: LocalTypeId) = when (val header = headerForFileNum(id.file)) {
        null -> {
            // referencing 0 is allowed, it means "current CU"
            if (id.file != 0) {
                log("unknown-header-num", "$id header not yet defined for $cu")
            }
            cu
        }

        else -> SourceFile.HeaderSource(header)
    }

    /**
     * Get all known file numbers in this CU's context.
     * Used for ref classification during materialization.
     */
    fun getAllFileNums(): Set<Int> = fileNumToHeader.keys
}
