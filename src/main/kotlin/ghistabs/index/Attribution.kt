package ghistabs.index

import ghidra.program.model.data.CategoryPath
import ghistabs.Demangler
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.*
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.TypeDecl

/**
 * Stdlib path marker. Requires `/usr|lib|include/` (plus one optional segment) before a stdlib
 * directory — guards against false positives like `/proj/src/c++_helpers/`.
 *
 * Two shapes, because toolchains nest the two the other way round: a stdlib directory *below* an
 * include root (`/usr/include/c++/3.4.4/bits/`), and an include root below a *toolchain* root
 * (`c:/mingw/include/`, `c:/mingw/lib/gcc-lib/mingw32/3.2.3/include/`). Only the first was matched,
 * so mingw's eighteen plain-C headers — `string.h`, `stdio.h`, `errno.h`, `sys/types.h`, gcc's own
 * `stddef.h` — were treated as possible homes for a user type and got an attribution vote. `lib`
 * stays out of the second shape's roots: a project's own `lib/include/` is far too ordinary.
 */
private val STD_MARKERS = Regex(
    """/(usr|lib|include)(/[^/]+)?/(mingw|cygwin|c\+\+|bits)/""" +
        """|/(mingw|cygwin|usr|gcc-lib)(/[^/]+)*?/include/""",
)

/** libstdc++'s own subdirectories, which are part of the spelling (`<bits/stl_alloc.h>`) rather than
 *  search roots like the version and target-config directories around them. */
private val STD_SUBDIRS = setOf("bits", "ext", "tr1", "tr2", "debug", "profile", "parallel", "backward")

/**
 * How a source is written as an `#include` directive, punctuation and all.
 *
 * A bare or relative spelling can only have come from a quoted include: cpp searches the *including*
 * file's own directory for `"…"` and never for `<…>` (`search_path_head`, gcc/cppfiles.c), and the
 * recorded name is the search directory joined to the spelling as written, so an empty directory
 * means the quote chain. That much is certain.
 *
 * A full path was found through some search directory, and the stabs do not say whether it was a
 * `-I` or a system one — gcc tracks that per directory (`cpp_dir.sysp`) and never writes it out. So
 * the rest is layout, and it is the same layout question [STD_MARKERS] already answers: what sits
 * under a system include root is spelled `<…>` relative to it, with the version and target-config
 * directories dropped (`c++/3.2.3/mingw32/bits/atomicity.h` is included as `<bits/atomicity.h>`).
 * Anything else stays quoted, keeping whatever directory it sits in below `include` — a project
 * header reached by `-I` really is written `"imageutil/appimage.h"`.
 */
fun includeSpelling(source: GhidraSourceFile): String {
    val segments = source.namedSegments
    fun quoted(spelling: String) = "\"" + spelling + "\""
    if (segments.size == 1 || source.hasArtificialRoot) return quoted(source.filename)
    val includeAt = segments.lastIndexOf("include")
    val below = if (includeAt >= 0) segments.drop(includeAt + 1) else listOf(segments.last())
    if (!source.path.isStdMarkerPath()) return quoted(below.joinToString("/"))
    val underCxxRoot = below.firstOrNull() == "c++" || below.firstOrNull() == "g++"
    val versionless = below.dropWhile { it == "c++" || it == "g++" || it.all { c -> c.isDigit() || c == '.' } }
    val spelled = when {
        underCxxRoot && versionless.size > 1 && versionless.first() !in STD_SUBDIRS -> versionless.drop(1)
        else -> versionless
    }
    return "<${spelled.joinToString("/")}>"
}

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
 * checksum — basename identity is the signal. Every spelling of one basename folds onto the
 * **fullest** of them, so long as the full ones **all agree on their last two directories**:
 * one physical header compiled under several build roots (`.../xvimage/image.h` from a Jenkins tree
 * and a devtools tree) keeps them, while genuinely distinct headers (`moduleA/config.h`,
 * `moduleB/config.h`, or mingw's `include/stdarg.h` against gcc's own) disagree and nothing folds.
 *
 * A path wins over the bare name because the render writes a source *tree*: a folded-to-bare
 * `image.h` landed at the top level next to `main.cpp` while the stabs knew it lived in
 * `result/include/xvimage/`. Among several equally-parented paths the **shallowest** wins,
 * lexicographic on a tie: two build roots are equally true, and the least deeply nested spelling is
 * the least specific to one of them, which keeps a library's headers together — `image.h` under the
 * Jenkins root while its siblings sat under the devtools root split one include tree in two.
 * Same-parent different-root false positives merge only render output; DTM attribution votes over
 * raw spellings and is unaffected.
 *
 * Which spelling wins is ours — it encodes gcc's two-spellings behaviour, which no platform API
 * models — but what it wins is a [GhidraSourceFile]: one identity per physical file, from here on.
 * Every input maps to itself unless it folds.
 */
fun foldSourcePaths(sources: Iterable<GhidraSourceFile>): Map<GhidraSourceFile, GhidraSourceFile> {
    fun isBare(s: GhidraSourceFile) = s.segments.size == 1

    // Two directory segments, not one: `include` alone is far too common a parent to identify a file
    // by. `c:/mingw/include/stdarg.h` and `c:/mingw/lib/gcc-lib/mingw32/3.2.3/include/stdarg.h` are
    // different headers that agree on it, and only the accident that one of them never reaches this
    // set kept them from merging. `mingw/include` against `3.2.3/include` separates them.
    fun parentDirs(s: GhidraSourceFile) = s.segments.dropLast(1).takeLast(2)

    val all = sources.toSet()
    val fold = all.groupBy { it.filename }.mapNotNull { (_, spellings) ->
        spellings.filterNot(::isBare)
            .takeIf { it.isNotEmpty() && it.mapTo(mutableSetOf(), ::parentDirs).size == 1 }
            ?.minWithOrNull(compareBy({ it.segments.size }, { it.path }))
            ?.let { fullest -> spellings.map { it to fullest } }
    }.flatten().toMap()
    return all.associateWith { fold[it] ?: it }
}

/** gcc emits anonymous types with CU-local sequential names; same name in different CUs is unrelated. */
fun Type.isCuLocalName() = name != null && (name.isEmpty() || CU_LOCAL_NAME.matches(name))

/**
 * The type's own demangled path, root-first (`std::string::_M_replace` → `["std", "string"]`), or null
 * when the stab carries no scope signal (method-less, or no member's mangled name demangles). Read off
 * any member's Itanium-mangled name: [Demangler.namespaces] yields the method's namespace, which IS the class's
 * full path. The leaf is the name Ghidra's `this`-param class-struct creator uses — which diverges from
 * the stabs spelling for abbreviation/typedef'd STL types (`Ss` demangles to `std::string`, not
 * `std::basic_string<char,…>`) — so it's what our type must be named to be reused rather than shadowed.
 */
fun Type.demangledClassPath(): List<String>? {
    val methods = (body as? TypeDecl.Struct<GlobalTypeId>)?.methods ?: return null
    return methods.firstNotNullOfOrNull { it.mangled?.let(Demangler::namespaces) }
}

/** The type's enclosing C++ scope, root-first — the category a namespace-organised DTM files it under
 *  (`std::string` → `["std"]` → `/std`; a global class → `[]` → ROOT). Null falls back to header
 *  attribution. See [demangledClassPath]. */
fun Type.enclosingScope(): List<String>? = demangledClassPath()?.dropLast(1)

/** A root-first scope path (from [enclosingScope]) as a DTM category; the empty scope is ROOT. */
fun scopeCategory(scope: List<String>): CategoryPath =
    scope.fold(CategoryPath.ROOT) { acc, seg -> CategoryPath(acc, seg) }

/**
 * Longest common path prefix across CUSource filenames in [sources]. Used to strip project
 * boilerplate from DTM categories. HeaderSource excluded — headers may live outside project root.
 */
fun commonProjectPrefix(sources: Collection<SourceFile>): String {
    val cuPaths = sources.filterIsInstance<SourceFile.CUSource>().map { it.identity.categorySegments }
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
    private val multiSourceHeaderHints: Map<String, GhidraSourceFile> = emptyMap(),
) {
    fun keyForAst(ast: Type, sources: Set<SourceFile>, diagnostics: StabsDiagnostics? = null): TypeLocation {
        val name = ast.ghidraName

        if (ast.isCuLocalName()) {
            return TypeLocation(strip(categoryPathOf(ast.cu.filename)) + "/anon", name)
        }

        return keyFor(name, sources, diagnostics)
    }

    fun keyFor(typeName: String, defSources: Set<SourceFile>, diagnostics: StabsDiagnostics? = null): TypeLocation {
        defSources.sorted().firstNotNullOfOrNull { stdRelativePath(it.filename) }?.let { rel ->
            diagnostics?.recordAttributionTrace(
                typeName = typeName,
                definingCUs = defSources,
                matchedCU = defSources.first { stdRelativePath(it.filename) == rel },
                routedTo = "/std/$rel",
                counter = "attribution-routed-std",
            )
            return TypeLocation("/std/$rel", typeName)
        }

        val realHeaders = defSources.filter { it.isRealHeader() }
        if (realHeaders.isNotEmpty()) {
            val owner = realHeaders.minBy { it.filename }
            return TypeLocation(strip(categoryPathOf(owner.filename)), typeName)
        }

        // Single canonical source — forward-EXCL collapses cross-CU HeaderSource instances
        // for the same physical file into one path here.
        val uniquePaths = defSources.map { it.filename }.toSet()
        if (uniquePaths.size == 1) {
            return TypeLocation(strip(categoryPathOf(uniquePaths.single())), typeName)
        }

        // gcc didn't BINCL the owning header, so defSources is .cpp-only. The hint map
        // (built from member-function SLINE majority) names the real header.
        multiSourceHeaderHints[typeName]?.let { hint ->
            return TypeLocation(strip(categoryPathOf(hint.path)), typeName)
        }

        return TypeLocation(strip(categoryPathOf(uniquePaths.min())) + "/multi", typeName)
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
    // `c++`/`g++` join the intermediates now that the marker can match at the toolchain root: for
    // `c:/mingw/include/c++/3.2.3/bits/stl_tree.h` the match ends after `/include/`, so the remainder
    // starts at `c++` and stopping there routed every libstdc++ type to one `/std/c++` bucket.
    val skipNames = setOf("bits", "ext", "tr1", "tr2", "debug", "profile", "parallel", "c++", "g++")
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
