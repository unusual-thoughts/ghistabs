package ghistabs.harvest

import ghistabs.diagnose.StabsDiagnostics
import ghistabs.parse.SourceFile

/**
 * STD_MARKERS regex: requires `/usr/`, `/lib/`, `/include/` (or one
 * intermediate segment after them) before a stdlib marker directory
 * (`mingw`, `cygwin`, `c++`, `bits`). Prevents false positives like
 * `/proj/src/c++_helpers/` matching as stdlib.
 */
private val STD_MARKERS = Regex("""/(usr|lib|include)(/[^/]+)?/(mingw|cygwin|c\+\+|bits)/""")

/** Strip a Windows drive-letter prefix (`c:`, `E:`, etc.) from a stabs path. */
private fun stripDriveLetter(path: String): String =
    if (path.length >= 2 && path[1] == ':' && path[0].isLetter()) path.substring(2) else path

private val CU_LOCAL_NAME = Regex("""\.?_anon_\d+""")

/**
 * "Real header" filename extensions — what gcc would normally `#include`
 * for declarations. `.tcc` is libstdc++'s template-implementation
 * convention (libstdc++ `bits/<file>.tcc`).
 *
 * Anything else (`.cpp`, `.c`, `.cc`, ...) hiding inside a [SourceFile.HeaderSource]
 * is a sibling translation unit that gcc registered via BINCL because some
 * other CU `#include`d it. It should not win attribution over actual headers.
 */
private val REAL_HEADER_EXTENSIONS = setOf("h", "hpp", "hh", "hxx", "h++", "tcc")

/**
 * Names that carry no cross-CU identity. gcc emits anonymous types with
 * CU-local sequential names (`._anon_82` etc.); same name in different CUs
 * refers to unrelated source-level types.
 */
fun TypeAst.isCuLocalName() = name != null && (name.isEmpty() || CU_LOCAL_NAME.matches(name))

/**
 * Compute the longest common path prefix across all CUSource filenames in
 * [sources]. Used by [Harvest] to strip project boilerplate from DTM
 * categories. Header sources are intentionally excluded — they can live
 * outside the project root (e.g. headers shared with stdlib).
 */
fun commonProjectPrefix(sources: Collection<SourceFile>): String {
    val cuPaths = sources.mapNotNull { (it as? SourceFile.CUSource)?.filename }
        .map { p -> stripDriveLetter(p).split('/').filter { it.isNotEmpty() } }
    if (cuPaths.isEmpty()) return ""
    val shortest = cuPaths.minBy { it.size }
    val prefix = mutableListOf<String>()
    for ((i, seg) in shortest.withIndex()) {
        if (cuPaths.all { i < it.size && it[i] == seg }) prefix += seg else break
    }
    // Drop the last segment if it looks like a filename (has an extension) — we
    // want a directory prefix, not a file prefix.
    if (prefix.isNotEmpty() && '.' in prefix.last()) prefix.removeLast()
    return if (prefix.isEmpty()) "" else prefix.joinToString("/", prefix = "/")
}

/**
 * Determine the canonical `(category, name)` slot in Ghidra's DataTypeManager
 * for a harvested type.
 *
 * Routing intent — preserve as much path information as possible so a user
 * browsing the DTM can see *where* a type came from:
 *
 *  - **Anonymous (CU-local) names** (`._anon_NN`, empty) → `<ast.cu>/anon`.
 *    gcc emits these with CU-local sequential numbering; the same name in
 *    two CUs refers to unrelated types.
 *  - **Stdlib paths** (`/usr/include/c++/...`, `/usr/include/mingw/...`,
 *    `/usr/lib/.../{c++,bits,mingw,cygwin}/...`) → `/std/<post-marker-path>`.
 *  - **Real-header preference** — if any defining source is a real header
 *    (`.h/.hpp/.hh/.hxx/.tcc`), route to that header. gcc's BINCL/EINCL
 *    mechanism produces HeaderSource even for sibling `.cpp` files; we
 *    skip those when a true header is available.
 *  - **Single canonical source** → that source's path.
 *  - **Multi-source** (no real-header owner) → lex-first path + `/multi`.
 *
 * Stripping the project prefix keeps DTM categories compact: e.g. on box2d
 * the project prefix is `/xml/box2d`, so `b2Hull` defined in
 * `/xml/box2d/include/box2d/collision.h` lands at
 * `/include/box2d/collision.h/b2Hull` instead of the full path.
 *
 * `..` segments are normalized away (`include/../src` → `src`).
 */
class Attribution(private val commonProjectPrefix: String = "") {
    fun keyForAst(ast: TypeAst, sources: Set<SourceFile>, diagnostics: StabsDiagnostics? = null): GhidraKey {
        val name = ast.ghidraName

        // 1. CU-local names: ignore the cross-CU `sources` set; route per-CU.
        if (ast.isCuLocalName()) {
            return GhidraKey(strip(norm(ast.cu.filename)) + "/anon", name)
        }

        return keyFor(name, sources, diagnostics)
    }

    fun keyFor(typeName: String, defSources: Set<SourceFile>, diagnostics: StabsDiagnostics? = null): GhidraKey {
        // 2. Stdlib path on any defining source.
        defSources.sorted().firstNotNullOfOrNull { stdRelativePath(it.filename) }?.let { rel ->
            diagnostics?.recordAttributionTrace(
                typeName = typeName,
                definingCUs = defSources,
                matchedCU = defSources.first { stdRelativePath(it.filename) == rel },
                routedTo = "/std/$rel",
                counter = "attribution-routed-std",
            )
            return GhidraKey("/std/$rel", typeName)
        }

        // 3. Real-header preference (see kdoc).
        val realHeaders = defSources.filter { it.isRealHeader() }
        if (realHeaders.isNotEmpty()) {
            val owner = realHeaders.minBy { it.filename }
            return GhidraKey(strip(norm(owner.filename)), typeName)
        }

        // 4. No real header. Single canonical source — all defSources share one
        //    filename path (cross-CU HeaderSource instances for the same physical
        //    file from forward-EXCL collapse here).
        val uniquePaths = defSources.map { it.filename }.toSet()
        if (uniquePaths.size == 1) {
            return GhidraKey(strip(norm(uniquePaths.single())), typeName)
        }

        // 5. Multi-source with no real-header owner: lex-first source + `/multi`.
        return GhidraKey(strip(norm(uniquePaths.min())) + "/multi", typeName)
    }

    /** Normalize a filesystem path: strip Windows drive letter, collapse `..`, drop empty segments. */
    private fun norm(path: String): String {
        val parts = stripDriveLetter(path).split('/').filter { it.isNotEmpty() && it != "." }
        val stack = ArrayDeque<String>()
        for (p in parts) {
            if (p == "..") {
                if (stack.isNotEmpty()) stack.removeLast() else stack.addLast(p)
            } else {
                stack.addLast(p)
            }
        }
        return stack.joinToString("/", prefix = "/")
    }

    /** Strip [commonProjectPrefix] from the start of a normalized path. */
    private fun strip(normalizedPath: String): String {
        if (commonProjectPrefix.isEmpty()) return normalizedPath
        if (!normalizedPath.startsWith(commonProjectPrefix)) return normalizedPath
        val rest = normalizedPath.removePrefix(commonProjectPrefix)
        return when {
            rest.isEmpty() -> "/"
            rest.startsWith("/") -> rest
            else -> "/$rest"
        }
    }
}

private fun SourceFile.isRealHeader(): Boolean = this is SourceFile.HeaderSource &&
    filename.substringAfterLast('.', "").lowercase() in REAL_HEADER_EXTENSIONS

/**
 * Extract the path AFTER a stdlib marker, preserving inner directory structure.
 * Strips version-number segments (`3.4.4`) and known intermediate dirs (`bits`,
 * `ext`, `tr1`, `debug`, ...) before returning the rest as the relative stdlib
 * basename.
 *
 * Example: `/usr/include/c++/3.4.4/bits/stl_vector.h`
 *   → marker matches `/include/c++/` (the `bits/` is in skip list)
 *   → after skipping: `stl_vector.h` → `stl_vector`.
 *
 * Returns null when no stdlib marker is present.
 */
private fun stdRelativePath(path: String): String? {
    val match = STD_MARKERS.find(path) ?: return null
    val startIdx = match.range.last + 1
    if (startIdx >= path.length) return null
    var current = path.substring(startIdx)
    val skipNames = setOf("bits", "ext", "tr1", "tr2", "debug", "profile", "parallel")
    while (current.isNotEmpty()) {
        val slash = current.indexOf('/')
        if (slash == -1) break
        val segment = current.substring(0, slash)
        if (segment.all { it.isDigit() || it == '.' } || segment in skipNames) {
            current = current.substring(slash + 1)
        } else {
            break
        }
    }
    val endIdx = current.indexOf('/')
    val basename = (if (endIdx == -1) current else current.substring(0, endIdx))
        .substringBeforeLast('.')
    return basename.ifEmpty { null }
}
