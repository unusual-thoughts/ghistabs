package ghistabs.parser

import java.util.ArrayDeque

/** Interface for logging sink used by IncludeContext. */
interface LogSink {
    fun log(
        tag: String,
        message: String,
    )
}

/**
 * Represents one BINCL-or-source-file entity. Two CUs that include or EXCL the same
 * (filename, checksum) share a single HeaderFile instance.
 */
data class HeaderFile(
    val filename: String,
    val checksum: Long,
    val originatingCu: String,
) {
    /**
     * Canonical identifier for this header: used for stable TypeId rewriting across CUs.
     * Derives from (filename, checksum) for BINCL headers, or the CU name for source files.
     */
    fun canonicalKey(): String =
        when {
            originatingCu == "<unknown>" -> "unknown_${filename}_$checksum"
            checksum != 0L -> "${filename}_${checksum.toString(16)}"
            else -> originatingCu
        }
}

/**
 * Maintains per-CU file context: file number → header mapping, include stack tracking,
 * and canonicalization of TypeIds across CUs that share included headers.
 *
 * BINCL/EINCL/EXCL handling:
 * - openSource: Start of CU, allocates fileNum=1 for the source file.
 * - switchSource: N_SOL, allocates next fileNum for line-number context.
 * - beginInclude: N_BINCL, allocates fileNum, registers/retrieves header globally, pushes stack.
 * - endInclude: N_EINCL, pops stack (no fileNum change).
 * - reMountExcluded: N_EXCL, allocates fileNum for shared header (or placeholder if forward EXCL).
 * - canonicalTypeId: Rewrites local TypeId to stable form across CUs sharing the same header.
 */
class IncludeContext(
    val cuFile: String,
    private val sink: LogSink,
) {
    private val fileNumToHeader: MutableMap<Int, HeaderFile> = mutableMapOf()
    private val includeStack: ArrayDeque<HeaderFile> = ArrayDeque()
    private var nextFileNum: Int = 1

    companion object {
        /** Global registry: (filename, checksum) → HeaderFile for cross-CU sharing. */
        object HeaderRegistry {
            val globalByFilenameChecksum: MutableMap<Pair<String, Long>, HeaderFile> = mutableMapOf()
        }
    }

    /**
     * Start of CU: allocates fileNum=1 and registers the CU's own source header.
     * Returns fileNum=1.
     */
    fun openSource(filename: String): Int {
        val fileNum = nextFileNum++
        val header = HeaderFile(filename, checksum = 0L, originatingCu = filename)
        fileNumToHeader[fileNum] = header
        return fileNum
    }

    /**
     * N_SOL: allocates next fileNum for line-number context within the CU.
     * These headers are local to the CU (not registered globally).
     */
    fun switchSource(filename: String): Int {
        val fileNum = nextFileNum++
        val header = HeaderFile(filename, checksum = 0L, originatingCu = cuFile)
        fileNumToHeader[fileNum] = header
        return fileNum
    }

    /**
     * N_BINCL: allocates fileNum, either retrieves the existing HeaderFile from the global registry
     * (if we've seen this (filename, checksum) before) or creates a new one and registers globally.
     * Pushes onto includeStack. Returns fileNum.
     */
    fun beginInclude(
        filename: String,
        checksum: Long,
    ): Int {
        val fileNum = nextFileNum++
        val key = filename to checksum
        val header =
            HeaderRegistry.globalByFilenameChecksum.getOrPut(key) {
                HeaderFile(filename, checksum, originatingCu = cuFile)
            }
        fileNumToHeader[fileNum] = header
        includeStack.push(header)
        return fileNum
    }

    /**
     * N_EINCL: pops the include stack. No fileNum change.
     */
    fun endInclude() {
        if (includeStack.isNotEmpty()) {
            includeStack.pop()
        }
    }

    /**
     * N_EXCL: allocates fileNum for a header that was previously INCLUDed (or will be later, in the case
     * of a forward EXCL). If the (filename, checksum) is already known globally, reuses it. Otherwise,
     * allocates a placeholder header with originatingCu = "<unknown>". Does NOT push includeStack.
     * Returns fileNum.
     */
    fun reMountExcluded(
        filename: String,
        checksum: Long,
    ): Int {
        val fileNum = nextFileNum++
        val key = filename to checksum
        val header =
            HeaderRegistry.globalByFilenameChecksum.getOrElse(key) {
                // Forward EXCL before BINCL: create placeholder
                sink.log("forward-excl", "$filename checksum=0x${checksum.toString(16)}")
                HeaderFile(filename, checksum, originatingCu = "<unknown>").also {
                    HeaderRegistry.globalByFilenameChecksum[key] = it
                }
            }
        fileNumToHeader[fileNum] = header
        return fileNum
    }

    /**
     * Lookup header for a given fileNum.
     */
    fun headerForFileNum(fileNum: Int): HeaderFile? = fileNumToHeader[fileNum]

    /**
     * Rewrites a local TypeId into a canonical form stable across CUs that share the same header.
     * For types defined inside a BINCL (header.originatingCu != cuFile), returns a TypeId keyed off
     * the header's canonical key. For local types, leaves TypeId as-is (but disambiguated by CU).
     */
    fun canonicalTypeId(localId: TypeId): TypeId {
        val header = headerForFileNum(localId.cu) ?: return localId

        // If this is a BINCL-originated header (not the CU's own source), canonicalize.
        if (header.checksum != 0L || header.originatingCu != cuFile) {
            // Use the header's canonical key as the CU identifier (as an integer hash).
            val canonicalCu = header.canonicalKey().hashCode()
            return TypeId(canonicalCu, localId.n)
        }

        // Local type: return as-is.
        return localId
    }
}
