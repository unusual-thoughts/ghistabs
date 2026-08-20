@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.program.model.address.Address
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.HeaderFile
import ghistabs.parse.LocalTypeId
import ghistabs.parse.SourceFile
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import java.util.*

/** Cross-CU dedup of header files via (filename, checksum) so BINCL/EXCL share one [HeaderFile]. */
class HeaderRegistry(sink: DiagnosticSink = DummySink) : DiagnosticSink by sink {
    /** (filename, checksum) → HeaderFile for cross-CU BINCL/EXCL sharing. */
    private val globalByFilenameChecksum = mutableMapOf<Pair<String, Long>, HeaderFile>()

    fun getOrInsert(filename: String, checksum: Long, cu: SourceFile.CUSource) =
        globalByFilenameChecksum.getOrPut(filename to checksum) {
            HeaderFile(filename, checksum, originatingCu = cu)
        }

    /**
     * Get-or-create for N_EXCL. Forward-EXCL case (N_EXCL seen before any N_BINCL): creates a
     * placeholder with `originatingCu = null` and registers it, so a later real BINCL gets the
     * same instance — keeping cross-CU Ref identity (canonicalization.md §6 D1).
     */
    fun recall(filename: String, checksum: Long): HeaderFile = globalByFilenameChecksum.getOrPut(filename to checksum) {
        debug("forward-excl", "$filename checksum=0x${checksum.toString(16)}")
        HeaderFile(filename, checksum, originatingCu = null)
    }

    /** Clear all registries (for test isolation). */
    fun clear() {
        globalByFilenameChecksum.clear()
    }
}

/** Per-CU `fileNum → header` map and BINCL/EINCL/EXCL stack tracking. */
@Serializable
class IncludeContext(
    val cu: SourceFile.CUSource,
    /** Where this CU's text began — the `Ltext0` its opening N_SO carries, absent when it carries 0. */
    val start: Address? = null,
    @Transient private val sink: DiagnosticSink = DummySink,
    @Transient val registry: HeaderRegistry = HeaderRegistry(sink),
) : DiagnosticSink by sink {
    private val fileNumToHeader: MutableMap<Int, HeaderFile> = mutableMapOf()

    @Transient
    private val includeStack: ArrayDeque<Int> = ArrayDeque()
    private var nextFileNum: Int = 1

    /** N_BINCL — allocate fileNum, share/register header globally, push stack. */
    fun beginInclude(filename: String, checksum: Long): Int {
        val fileNum = nextFileNum++
        fileNumToHeader[fileNum] = registry.getOrInsert(filename, checksum, cu)
        includeStack.push(fileNum)
        return fileNum
    }

    /** N_EINCL — pop include stack. Warns on empty stack (unbalanced). */
    fun endInclude() {
        if (includeStack.isNotEmpty()) {
            includeStack.pop()
        } else {
            warn("einc-unbalanced", "endInclude with empty stack")
        }
    }

    val currentInclude get() = includeStack.lastOrNull()?.let { fileNumToHeader[it] }

    /** N_EXCL — allocate fileNum sharing a known header, or a forward-EXCL placeholder. Does NOT push stack. */
    fun remount(filename: String, checksum: Long): Int {
        val fileNum = nextFileNum++
        fileNumToHeader[fileNum] = registry.recall(filename, checksum)
        return fileNum
    }

    internal fun headerForFileNum(fileNum: Int): HeaderFile? = fileNumToHeader[fileNum]

    /**
     * `id.file == 0` → [SourceFile.CUSource]. `id.file > 0` with known header → [SourceFile.HeaderSource].
     * Missing entry falls back to CUSource and logs `unknown-header-num`.
     */
    fun sourceFor(id: LocalTypeId) = when (val header = headerForFileNum(id.file)) {
        null -> {
            if (id.file != 0) { // 0 = current CU, expected
                log("unknown-header-num", "$id header not yet defined for $cu")
            }
            cu
        }

        else -> SourceFile.HeaderSource(header)
    }

    fun getAllFileNums(): Set<Int> = fileNumToHeader.keys
}
