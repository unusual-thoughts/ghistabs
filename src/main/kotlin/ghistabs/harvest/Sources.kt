package ghistabs.harvest

import ghidra.util.SourceFileUtils

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
fun sourceFileOf(spelling: String) = GhidraSourceFile(SourceFileUtils.normalizeDwarfPath(spelling, STABS_ROOT))

/** [sourceFileOf] for a spelling gcc may have left empty (no `N_SOL` in effect). */
fun sourceFileOrNull(spelling: String?) = spelling?.takeIf { it.isNotBlank() }?.let(::sourceFileOf)

/** Path segments: `/c:/mingw/include/x.h` → `[c:, mingw, include, x.h]`. Normalisation has already
 *  settled separators, drive letters and `..`, so this is a split and nothing more. */
val GhidraSourceFile.segments get() = path.split('/').filter { it.isNotEmpty() }
val GhidraSourceFile.rootSegment get() = segments.firstOrNull()
val String.isDriveLetter get() = length == 2 && this[0].isLetter() && this[1] == ':'
val GhidraSourceFile.inWindowsDrive get() = rootSegment?.isDriveLetter ?: false

/** The segments that name the file rather than the volume it sits on. */
val GhidraSourceFile.namedSegments get() = segments.drop(if (inWindowsDrive) 1 else 0)

/** The path is rooted only because normalisation rooted it: gcc wrote the spelling relative (`./x.h`,
 *  `../../x.h`) or bare, and [STABS_ROOT] stands in for the directory it was relative to. Where the
 *  spelling *says* it is relative and no compilation directory anchored it, that is all we know about
 *  where the file sits — so nothing above the file's own name can be read off the path. */
val GhidraSourceFile.hasArtificialRoot get() = ARTIFICIAL_ROOT.matches(rootSegment.orEmpty())

private val ARTIFICIAL_ROOT = Regex("${STABS_ROOT}(_\\d+)?")
