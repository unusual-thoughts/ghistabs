@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.HeaderFile
import ghistabs.parse.LocalTypeId
import ghistabs.parse.SourceFile
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import java.util.*

/**
 * Global registry for header files shared across multiple CUs via BINCL/EXCL.
 * Maintains canonical CU integer mapping to avoid hashCode() collisions.
 */
class HeaderRegistry(val sink: DiagnosticSink = DummySink) : DiagnosticSink by sink {
    /** (filename, checksum) → HeaderFile for cross-CU BINCL/EXCL sharing. */
    private val globalByFilenameChecksum = mutableMapOf<Pair<String, Long>, HeaderFile>()

    fun getOrInsert(filename: String, checksum: Long, cu: SourceFile.CUSource) =
        globalByFilenameChecksum.getOrPut(filename to checksum) {
            HeaderFile(filename, checksum, originatingCu = cu)
        }

    /**
     * Retrieves or creates a [HeaderFile] for an N_EXCL (header remount) record.
     *
     * Forward EXCL case: if `N_EXCL` is encountered before any CU has processed the corresponding
     * `N_BINCL`, this method creates a placeholder [HeaderFile] with `originatingCu = null` and
     * stores it in [globalByFilenameChecksum] so that a later [getOrInsert] for the same key
     * returns the same instance. This resolves stabs-canonicalization.md §6 deviation D1: types
     * referenced via the placeholder share a single [HeaderFile] identity with types defined by
     * the real BINCL, so their [ghistabs.parse.GlobalTypeId]s agree and cross-CU Ref lookup succeeds.
     */
    fun recall(filename: String, checksum: Long): HeaderFile = globalByFilenameChecksum.getOrPut(filename to checksum) {
        log("forward-excl", "$filename checksum=0x${checksum.toString(16)}")
        HeaderFile(filename, checksum, originatingCu = null)
    }

    /** Clear all registries (for test isolation). */
    fun clear() {
        globalByFilenameChecksum.clear()
    }
}

/**
 * Maintains per-CU file context: file number → header mapping, include stack tracking.
 *
 * BINCL/EINCL/EXCL handling:
 * - [beginInclude]: N_BINCL, allocates fileNum, registers/retrieves header globally, pushes stack.
 * - [endInclude]: N_EINCL, pops stack (no fileNum change).
 * - [remount]: N_EXCL, allocates fileNum for shared header (or placeholder if forward EXCL).
 * - [sourceFor]: converts [ghistabs.parse.LocalTypeId] to [SourceFile] by looking up fileNum in header map.
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
     * N_EXCL: allocates fileNum for a header that was previously INCLUDed (or will be later, in the
     * case of a forward EXCL). If the (filename, checksum) is already known globally, reuses it.
     * Otherwise, allocates a placeholder header with `originatingCu = null` AND registers it
     * globally so a later real BINCL returns the same instance (see [HeaderRegistry.recall]).
     * Does NOT push includeStack. Returns fileNum.
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

    /**
     * Returns the [SourceFile] for a [ghistabs.parse.LocalTypeId], handling both CU-level and header-level types.
     *
     * Lookup contract:
     * - If `id.file == 0`, return [CUSource] (CU-level type).
     * - If `id.file > 0` and a header is registered for this fileNum, return [HeaderSource] wrapping
     *   the [HeaderFile].
     * - If `id.file > 0` but the fileNum has no header entry (missing BINCL or forward EXCL case),
     *   fall back to [CUSource] and log `unknown-header-num`.
     *
     * This ensures consistent [ghistabs.parse.GlobalTypeId] formation: two types with the same [ghistabs.parse.LocalTypeId] but
     * processed in different CUs receive the same [SourceFile] instance if and only if the header
     * mapping is identical.
     */
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
