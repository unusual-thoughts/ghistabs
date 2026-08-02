package ghistabs.harvest

import ghidra.program.model.data.CategoryPath
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.namespaceChain
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.TypeDecl

/**
 * Stdlib path marker. Requires `/usr|lib|include/` (plus one optional segment) before a stdlib
 * directory — guards against false positives like `/proj/src/c++_helpers/`.
 */
private val STD_MARKERS = Regex("""/(usr|lib|include)(/[^/]+)?/(mingw|cygwin|c\+\+|bits)/""")

/** Strip a Windows drive-letter prefix (`c:`, `E:`, …) from a stabs path. */
private fun stripDriveLetter(path: String): String =
    if (path.length >= 2 && path[1] == ':' && path[0].isLetter()) path.substring(2) else path

/** Path segments, drive letter dropped and both separators honoured (stabs mixes `/` and `\`). */
private fun pathSegments(path: String) = stripDriveLetter(path).split('/', '\\').filter { it.isNotEmpty() }

/** Last path segment of a stabs path: `c:/mingw/include/c++/3.2.3/bits/stl_alloc.h` → `stl_alloc.h`. */
fun String.pathBasename() = pathSegments(this).lastOrNull() ?: this

private val CU_LOCAL_NAME = Regex("""\.?_anon_\d+""")

/**
 * Real-header extensions (`.tcc` is libstdc++'s template-impl convention). A `.cpp`/`.cc`/`.c`
 * inside a [SourceFile.HeaderSource] means another CU `#include`d that TU — it must NOT win
 * attribution over actual headers.
 */
private val REAL_HEADER_EXTENSIONS = setOf("h", "hpp", "hh", "hxx", "h++", "tcc")

/** Filename has a header extension we trust as a "real" header for attribution. */
fun String.hasHeaderExtension(): Boolean = substringAfterLast('.', "").lowercase() in REAL_HEADER_EXTENSIONS

/** Path lies under a stdlib include root — never the "home" of a user type, so excluded from attribution votes. */
fun String.isStdMarkerPath(): Boolean = STD_MARKERS.containsMatchIn(this)

/**
 * Fold source-filename spellings so one physical file yields one output file (§15).
 *
 * gcc spells the same header two ways across CUs: the full include path where it compiles the
 * definitions, and the bare `#include "x.h"` spelling where another TU only forward-references it.
 * Each CU's N_BINCL carries a different checksum (its own expansion), so they can't be merged by
 * checksum — basename identity is the signal. A **bare** name (no path separator) that is the
 * basename of full paths also present folds those full paths onto the bare spelling: the shorter
 * name wins and is what displays. One physical header compiled under several build roots keeps its
 * immediate parent directory (`.../xvimage/image.h` from a Jenkins tree and a devtools tree), so
 * full paths fold when they **all agree on that parent** — including the single-path case. Guard:
 * genuinely distinct headers sharing a basename (`moduleA/config.h`, `moduleB/config.h`) disagree
 * on the parent, so nothing folds. Same-parent different-root false positives merge only render
 * output; DTM attribution votes over raw spellings and is unaffected.
 *
 * Returns raw spelling → folded spelling; every input maps to itself unless it folds.
 */
fun foldSourcePaths(filenames: Iterable<String>): Map<String, String> {
    fun isBare(s: String) = '/' !in s && '\\' !in s
    fun parentDir(s: String) = pathSegments(s).dropLast(1).lastOrNull().orEmpty()

    val all = filenames.toSet()
    val fullPathsByBasename = all.filterNot(::isBare).groupBy(String::pathBasename)
    val fold = mutableMapOf<String, String>()
    for (name in all) {
        if (!isBare(name)) continue
        val fulls = fullPathsByBasename[name] ?: continue
        if (fulls.mapTo(mutableSetOf(), ::parentDir).size == 1) fulls.forEach { fold[it] = name }
    }
    return all.associateWith { fold[it] ?: it }
}

/** gcc emits anonymous types with CU-local sequential names; same name in different CUs is unrelated. */
fun TypeAst.isCuLocalName() = name != null && (name.isEmpty() || CU_LOCAL_NAME.matches(name))

/**
 * The type's own demangled path, root-first (`std::string::_M_replace` → `["std", "string"]`), or null
 * when the stab carries no scope signal (method-less, or no member's mangled name demangles). Read off
 * any member's Itanium-mangled name: [namespaceChain] yields the method's namespace, which IS the class's
 * full path. The leaf is the name Ghidra's `this`-param class-struct creator uses — which diverges from
 * the stabs spelling for abbreviation/typedef'd STL types (`Ss` demangles to `std::string`, not
 * `std::basic_string<char,…>`) — so it's what our type must be named to be reused rather than shadowed.
 */
fun TypeAst.demangledClassPath(): List<String>? {
    val methods = (body as? TypeDecl.Struct<GlobalTypeId>)?.methods ?: return null
    return methods.firstNotNullOfOrNull { it.mangled?.let(::namespaceChain) }
}

/** The type's enclosing C++ scope, root-first — the category a namespace-organised DTM files it under
 *  (`std::string` → `["std"]` → `/std`; a global class → `[]` → ROOT). Null falls back to header
 *  attribution. See [demangledClassPath]. */
fun TypeAst.enclosingScope(): List<String>? = demangledClassPath()?.dropLast(1)

/** A root-first scope path (from [enclosingScope]) as a DTM category; the empty scope is ROOT. */
fun scopeCategory(scope: List<String>): CategoryPath =
    scope.fold(CategoryPath.ROOT) { acc, seg -> CategoryPath(acc, seg) }

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
class Attribution(
    private val commonProjectPrefix: String = "",
    private val multiSourceHeaderHints: Map<String, String> = emptyMap(),
) {
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

        // gcc didn't BINCL the owning header, so defSources is .cpp-only. The hint map
        // (built from member-function SLINE majority) names the real header.
        multiSourceHeaderHints[typeName]?.let { hint ->
            return GhidraKey(strip(norm(hint)), typeName)
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
