@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.program.model.address.Address
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.HeaderFile
import ghistabs.parse.Language
import ghistabs.parse.LocalTypeId
import ghistabs.parse.SourceFile
import ghistabs.rangeUntil
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

/**
 * One CU's scope: the text it declared between its opening and closing N_SO, its `fileNum → header`
 * map, and the BINCL/EINCL/EXCL stack that fills it.
 */
@Serializable
class CuContext(
    val cu: SourceFile.CUSource,
    @Transient private val sink: DiagnosticSink = DummySink,
    @Transient val registry: HeaderRegistry = HeaderRegistry(sink),
    val language: Language? = null,
    /** Where this CU's text began — the `Ltext0` its opening N_SO carries, absent when it carries 0. */
    val start: Address? = null,
) : DiagnosticSink by sink {
    private var end: Address? = null

    /** The closing (empty-name) N_SO's `Ltext`, absent when it carries 0. */
    fun endAt(addr: Address?) {
        end = addr
    }

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
                degradation("unknown-header-num", "$cu", "$id header not yet defined")
            }
            cu
        }

        else -> SourceFile.HeaderSource(header)
    }

    fun getAllFileNums(): Set<Int> = fileNumToHeader.keys

    /**
     * The range between two boundaries, or null where there is none to make: an address missing, or the
     * two landing together — an N_SO and the N_SOL after it share one address, and a CU can bracket no
     * text at all. Ghidra's ends are inclusive, so the exclusive [end] loses one on the way in.
     */
    fun addressRange() = start?.let { s ->
        when (val e = end) {
            null -> null.also { debug("unfinished-cu", "$cu has no end address @$s") }
            else if e == s -> null.also { debug("empty-cu-range", "$cu range empty @$e, must be comdat") }
            else if e < s -> null.also { err("inverted-cu-range", "$cu range inverted $s..$e") }
            else -> s..<e
        }
    }
}
