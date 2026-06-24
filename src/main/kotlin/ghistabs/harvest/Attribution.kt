package ghistabs.harvest

import ghistabs.diagnose.StabsDiagnostics
import ghistabs.parse.SourceFile

/**
 * Stdlib path marker. Requires `/usr|lib|include/` (plus one optional segment) before a stdlib
 * directory — guards against false positives like `/proj/src/c++_helpers/`.
 */
private val STD_MARKERS = Regex("""/(usr|lib|include)(/[^/]+)?/(mingw|cygwin|c\+\+|bits)/""")

/** Strip a Windows drive-letter prefix (`c:`, `E:`, …) from a stabs path. */
private fun stripDriveLetter(path: String): String =
    if (path.length >= 2 && path[1] == ':' && path[0].isLetter()) path.substring(2) else path

private val CU_LOCAL_NAME = Regex("""\.?_anon_\d+""")

/**
 * Real-header extensions (`.tcc` is libstdc++'s template-impl convention). A `.cpp`/`.cc`/`.c`
 * inside a [SourceFile.HeaderSource] means another CU `#include`d that TU — it must NOT win
 * attribution over actual headers.
 */
private val REAL_HEADER_EXTENSIONS = setOf("h", "hpp", "hh", "hxx", "h++", "tcc")

/** gcc emits anonymous types with CU-local sequential names; same name in different CUs is unrelated. */
fun TypeAst.isCuLocalName() = name != null && (name.isEmpty() || CU_LOCAL_NAME.matches(name))

/**
 * Longest common path prefix across CUSource filenames in [sources]. Used to strip project
 * boilerplate from DTM categories. HeaderSource excluded — headers may live outside project root.
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
    // Want a directory prefix, not a file prefix.
    if (prefix.isNotEmpty() && '.' in prefix.last()) prefix.removeLast()
    return if (prefix.isEmpty()) "" else prefix.joinToString("/", prefix = "/")
}

/**
 * Routes a harvested type to its canonical `(category, name)` slot in the DTM.
 *
 * Resolution order:
 *  1. CU-local anonymous name (`._anon_NN`, empty) → `<ast.cu>/anon`.
 *  2. Stdlib path → `/std/<post-marker-path>`.
 *  3. Real-header preference (`.h/.hpp/.hh/.hxx/.tcc`) — gcc's BINCL/EINCL surfaces
 *     sibling `.cpp` files as HeaderSource; those must lose to actual headers.
 *  4. Single canonical source → that source's path.
 *  5. Multi-source, no header owner → lex-first path + `/multi`.
 *
 * Strips [commonProjectPrefix] for compact categories; normalises `..` segments.
 */
class Attribution(private val commonProjectPrefix: String = "") {
    fun keyForAst(ast: TypeAst, sources: Set<SourceFile>, diagnostics: StabsDiagnostics? = null): GhidraKey {
        val name = ast.ghidraName

        if (ast.isCuLocalName()) {
            return GhidraKey(strip(norm(ast.cu.filename)) + "/anon", name)
        }

        return keyFor(name, sources, diagnostics)
    }

    fun keyFor(typeName: String, defSources: Set<SourceFile>, diagnostics: StabsDiagnostics? = null): GhidraKey {
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

        val realHeaders = defSources.filter { it.isRealHeader() }
        if (realHeaders.isNotEmpty()) {
            val owner = realHeaders.minBy { it.filename }
            return GhidraKey(strip(norm(owner.filename)), typeName)
        }

        // Single canonical source — forward-EXCL collapses cross-CU HeaderSource instances
        // for the same physical file into one path here.
        val uniquePaths = defSources.map { it.filename }.toSet()
        if (uniquePaths.size == 1) {
            return GhidraKey(strip(norm(uniquePaths.single())), typeName)
        }

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
 * Path AFTER a stdlib marker, skipping version segments (`3.4.4`) and known intermediates
 * (`bits`, `ext`, `tr1`, `debug`, …). Returns the basename (no extension), or null if no marker.
 *
 * Example: `/usr/include/c++/3.4.4/bits/stl_vector.h` → `stl_vector`.
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
