package ghistabs.harvest

import ghidra.util.SourceFileUtils
import ghistabs.parse.SourceFile
import ghistabs.parse.isDriveLetter
import ghistabs.parse.segments
import java.util.concurrent.ConcurrentHashMap

/** Ghidra's source-file identity, aliased because [ghistabs.parse.SourceFile] — the CU-vs-header
 *  distinction Ghidra has no field for — is in scope alongside it nearly everywhere. */
typealias GhidraSourceFile = ghidra.program.database.sourcemap.SourceFile

/** Artificial root [SourceFileUtils.normalizeDwarfPath] anchors a relative spelling under. */
private const val STABS_ROOT = "stabs"

/**
 * A stabs spelling as the identity Ghidra models it with.
 *
 * [GhidraSourceFile] demands a path that is non-blank, URI-normalisable and absolute — which none of
 * gcc's three shapes are: `c:/mingw/include/c++/3.2.3/bits/stl_vector.h` and `C:\work\include\foo.h`
 * are drive-relative, `header.h` is bare. `normalizeDwarfPath` is built for exactly that set and
 * takes all of them: the drive letter survives as a leading segment (`/c:/mingw/…`, a URI is happy
 * with a colon once the path is rooted), backslashes become slashes, and a bare or `./`-relative
 * spelling is anchored under `/stabs`. So no shape of ours throws, and nothing is skipped —
 * `DWARFImporter` catches the throw and drops the file, which would silently lose a source here.
 */
fun sourceFileOf(spelling: String): GhidraSourceFile = identities.computeIfAbsent(spelling) {
    GhidraSourceFile(SourceFileUtils.normalizeDwarfPath(it, STABS_ROOT))
}

/** Normalisation parses a URI, and the harvest asks for one type's source once per pass over the
 *  types — so the same few hundred spellings are normalised tens of thousands of times a run. Pure
 *  function of the spelling, so a process-wide memo is sound; it holds one entry per spelling any
 *  binary in the session mentioned. */
private val identities = ConcurrentHashMap<String, GhidraSourceFile>()

/** [sourceFileOf] for a spelling gcc may have left empty (no `N_SOL` in effect). */
fun sourceFileOrNull(spelling: String?) = spelling?.takeIf { it.isNotBlank() }?.let(::sourceFileOf)

/**
 * The file a stab-stream source names.
 *
 * [SourceFile] identifies a *scope in the stab stream* — a CU, or one CU's BINCL block keyed by gcc's
 * per-expansion checksum — which is what type ids resolve against, so it stays keyed by the raw
 * spelling. This is the one conversion from that to the physical file it names, rather than each
 * consumer reaching through `.filename` itself.
 */
val SourceFile.identity get() = when (this) {
    // A CU's directory-N_SO is the only spelling gcc gives it. Resolving here rather than at render
    // time via the old `cuDirectories` map puts a CU on the same key its own N_SOL/N_BINCL already
    // use — those go through `resolved()` — so one file is one row from the harvest onward.
    is SourceFile.CUSource -> sourceFileOf(spelling)

    is SourceFile.HeaderSource -> sourceFileOf(filename)
}

/** Path segments: `/c:/mingw/include/x.h` → `[c:, mingw, include, x.h]`. Normalisation has already
 *  settled separators, drive letters and `..`, so this is a split and nothing more. */
val GhidraSourceFile.segments get() = path.segments
val GhidraSourceFile.rootSegment get() = segments.firstOrNull()
val GhidraSourceFile.inWindowsDrive get() = rootSegment?.isDriveLetter ?: false

/** The segments that name the file rather than the volume it sits on. */
val GhidraSourceFile.namedSegments get() = segments.drop(if (inWindowsDrive) 1 else 0)

/** The path is rooted only because normalisation rooted it: gcc wrote the spelling relative (`./x.h`,
 *  `../../x.h`) or bare, and [STABS_ROOT] stands in for the directory it was relative to. Where the
 *  spelling *says* it is relative and no compilation directory anchored it, that is all we know about
 *  where the file sits — so nothing above the file's own name can be read off the path. */
val GhidraSourceFile.hasArtificialRoot get() = ARTIFICIAL_ROOT.matches(rootSegment.orEmpty())

private val ARTIFICIAL_ROOT = Regex("${STABS_ROOT}(_\\d+)?")

/**
 * The spelling [path] normalises to, as a DTM category prefix: rooted, separators and `..` settled,
 * with neither the volume nor the artificial root — a category says which file a declaration belongs
 * to, and `/stabs` is not a place any declaration lives.
 *
 * The one normalisation the whole harvest shares, rather than each consumer collapsing `..` and
 * stripping `c:` its own way.
 */
fun categoryPathOf(spelling: String) = sourceFileOf(spelling).categorySegments.joinToString("/", prefix = "/")

/** [namedSegments] without the root normalisation invented for a relative spelling. */
val GhidraSourceFile.categorySegments get() = namedSegments.drop(if (hasArtificialRoot) 1 else 0)
