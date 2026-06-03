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
class HeaderRegistry {
    /** (filename, checksum) → HeaderFile for cross-CU BINCL/EXCL sharing. */
    @Transient
    val globalByFilenameChecksum: MutableMap<Pair<String, Long>, HeaderFile> = mutableMapOf()

    /** Canonical CU integers: (filename, checksum) key → unique integer (collision-free). */
    private val canonicalCuByKey: MutableMap<String, Int> = mutableMapOf()

    /**
     * Allocates a canonical CU integer for a header key (string form of (filename, checksum)).
     * Uses a counter to ensure no collisions, unlike hashCode().
     */
    fun allocateCanonicalCu(key: String): Int = canonicalCuByKey.getOrPut(key) {
        canonicalCuByKey.size + 1
    }

    /** Clear all registries (for test isolation). */
    fun clear() {
        globalByFilenameChecksum.clear()
        canonicalCuByKey.clear()
    }
}

/**
 * Represents one BINCL-or-source-file entity. Two CUs that include or EXCL the same
 * (filename, checksum) share a single HeaderFile instance.
 */
@Serializable
data class HeaderFile(val filename: String, val checksum: Long, val originatingCu: String) {
    /**
     * Canonical identifier for this header: used for stable TypeId rewriting across CUs.
     * Derives from (filename, checksum) for BINCL headers, or the CU name for source files.
     */
    fun canonicalKey(): String = when {
        originatingCu == "<unknown>" -> "unknown_${filename}_$checksum"
        checksum != 0L -> "${filename}_${checksum.toString(16)}"
        // No checksum: scope by (originatingCu, filename). Without the
        // filename, two different non-checksummed headers first seen in
        // the same CU would collide. Without `originatingCu`, headers
        // with the same name first seen in different CUs would collide.
        else -> "$originatingCu#$filename"
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
@Serializable
class IncludeContext(
    val cuFile: String,
    @Transient private val sink: DiagnosticSink = DummySink,
    @Transient val registry: HeaderRegistry = HeaderRegistry(),
) : DiagnosticSink by sink {
    private val fileNumToHeader: MutableMap<Int, HeaderFile> = mutableMapOf()

    @Transient
    private val includeStack: ArrayDeque<HeaderFile> = ArrayDeque()
    private var nextFileNum: Int = 1

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
    fun beginInclude(filename: String, checksum: Long): Int {
        val fileNum = nextFileNum++
        val key = filename to checksum
        val header = registry.globalByFilenameChecksum.getOrPut(key) {
            HeaderFile(filename, checksum, originatingCu = cuFile)
        }
        fileNumToHeader[fileNum] = header
        includeStack.push(header)
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

    /**
     * N_EXCL: allocates fileNum for a header that was previously INCLUDed (or will be later, in the case
     * of a forward EXCL). If the (filename, checksum) is already known globally, reuses it. Otherwise,
     * allocates a placeholder header with originatingCu = "<unknown>". Does NOT push includeStack.
     * The placeholder is registered ONLY in the local fileNumToHeader, NOT in the global registry,
     * so a later real BINCL gets its own slot and the forward-EXCL CU's types diverge from it.
     * Returns fileNum.
     */
    fun reMountExcluded(filename: String, checksum: Long): Int {
        val fileNum = nextFileNum++
        val key = filename to checksum
        val header = registry.globalByFilenameChecksum[key] ?: run {
            // Forward EXCL before BINCL: create placeholder, store only locally
            log("forward-excl", "$filename checksum=0x${checksum.toString(16)}")
            HeaderFile(filename, checksum, originatingCu = "<unknown>")
        }
        fileNumToHeader[fileNum] = header
        return fileNum
    }

    /**
     * Lookup header for a given fileNum.
     */
    fun headerForFileNum(fileNum: Int): HeaderFile? = fileNumToHeader[fileNum]

    /**
     * Get all known file numbers in this CU's context.
     * Used for ref classification during materialization.
     */
    fun getAllFileNums(): Set<Int> = fileNumToHeader.keys

    /**
     * Rewrites a local TypeId into a canonical form stable across CUs that share the same header.
     *
     * Single rule: if there's a known header for this file slot, use the
     * header's canonical key (which already encodes `(filename, checksum)`
     * or `(originatingCu, filename)`); otherwise fall back to a per-CU,
     * per-fileNum bucket (the `(0, n)` builtin-reference slot and
     * placeholders land here).
     *
     * The previous form split the same-cuFile-no-checksum case off into
     * `cuFile#fileN`, which produced different canonical keys for the
     * SAME shared header across CUs — e.g. `Keywords.cpp`'s stl_multiset.h
     * landed at `Keywords.cpp#file143` while `inst.cpp`'s identical entry
     * for stl_multiset.h landed at `Keywords.cpp` via `canonicalKey()`,
     * so refs from `inst.cpp` to types defined there (e.g. EnumInstToken
     * pulled in by BranchInstructions's array element) failed to resolve.
     */
    fun canonicalTypeId(localId: TypeId): TypeId {
        val header = headerForFileNum(localId.cu)
        val key = header?.canonicalKey() ?: "$cuFile#file${localId.cu}"
        val canonicalCu = registry.allocateCanonicalCu(key)
        return TypeId(canonicalCu, localId.n)
    }

    /**
     * Canonicalizes all TypeIds within a TypeDecl tree (refs, inline defs, etc.).
     * Recursively walks the TypeDecl structure and rewrites TypeIds via canonicalTypeId().
     */
    fun canonicalizeTypeDecl(decl: TypeDecl): TypeDecl = when (decl) {
        is TypeDecl.Ref -> TypeDecl.Ref(canonicalTypeId(decl.id))
        is TypeDecl.Range -> TypeDecl.Range(canonicalTypeId(decl.of), decl.min, decl.max)
        is TypeDecl.Pointer -> TypeDecl.Pointer(canonicalizeTypeDecl(decl.pointee))
        is TypeDecl.Reference -> TypeDecl.Reference(canonicalizeTypeDecl(decl.referent))
        is TypeDecl.Const -> TypeDecl.Const(canonicalizeTypeDecl(decl.inner))
        is TypeDecl.Volatile -> TypeDecl.Volatile(canonicalizeTypeDecl(decl.inner))
        is TypeDecl.Array -> TypeDecl.Array(
            canonicalizeTypeDecl(decl.element),
            decl.length,
            decl.indexType?.let { canonicalizeTypeDecl(it) },
        )

        is TypeDecl.Enum -> decl // Enums have no TypeId references
        is TypeDecl.Struct -> TypeDecl.Struct(
            decl.kind,
            decl.sizeBytes,
            decl.bases.map { BaseDecl(canonicalizeTypeDecl(it.type), it.isVirtual, it.access, it.offsetBits) },
            decl.fields.map {
                FieldDecl(
                    it.name,
                    canonicalizeTypeDecl(it.type),
                    it.offsetBits,
                    it.sizeBits,
                    it.isStatic,
                )
            },
            decl.methods.map {
                MethodDecl(
                    it.name,
                    it.mangled,
                    canonicalizeTypeDecl(it.signature),
                    it.access,
                    it.virt,
                    it.isConst,
                    it.isVolatile,
                    it.vtableOffsetBits,
                )
            },
            decl.hasVTablePointerMarker,
            decl.vtableTargetTypeId?.let { canonicalTypeId(it) },
        )

        is TypeDecl.FunctionT -> TypeDecl.FunctionT(
            canonicalizeTypeDecl(decl.ret),
            decl.params.map { canonicalizeTypeDecl(it) },
        )

        is TypeDecl.Method -> TypeDecl.Method(
            canonicalizeTypeDecl(decl.cls),
            canonicalizeTypeDecl(decl.ret),
            decl.params.map { canonicalizeTypeDecl(it) },
        )

        is TypeDecl.Complex -> decl
        is TypeDecl.XRef -> decl
        is TypeDecl.WithSizeAttr -> TypeDecl.WithSizeAttr(decl.sizeBits, canonicalizeTypeDecl(decl.inner))
        is TypeDecl.InlineDef -> TypeDecl.InlineDef(canonicalTypeId(decl.id), canonicalizeTypeDecl(decl.body))
        TypeDecl.Builtin -> decl
    }
}
