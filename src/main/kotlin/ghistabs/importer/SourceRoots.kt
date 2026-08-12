package ghistabs.importer

import ghidra.program.database.sourcemap.UserDataPathTransformer
import ghidra.program.model.listing.Program
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.harvest.GhidraSourceFile
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.isDirectory
import kotlin.io.path.name
import kotlin.streams.asSequence

/** A recorded source directory and the local directory it was found in, both trailing-slashed. */
data class DirectoryTransform(val recorded: String, val local: String)

/** What a root did and did not account for. [ambiguous] carries the tied candidates, so a report can
 *  name them rather than say only that something was unclear. */
data class RootDerivation(
    val transforms: List<DirectoryTransform>,
    val ambiguous: Map<String, List<String>>,
    val unmatched: List<String>,
)

/**
 * Match recorded source directories onto directories under a local checkout.
 *
 * Per *directory*, not per file: a build records `c:/mingw/include/c++/3.2.3/bits/` for eighteen
 * headers, and where that directory lives locally is one question with one answer.
 *
 * Two criteria, in order. The trailing path segments a candidate shares with the recorded directory
 * — `…/util/project/` under a project checkout is the same directory, whatever is above it. Then the
 * filenames: the recorded directory's own files must actually be in the candidate. gcc's own tree has
 * twenty-five directories called `bits`, all tying on the first criterion, and only
 * `libstdc++-v3/include/bits` holds `stl_vector.h`.
 *
 * The second criterion is evidence, not a tie-break of convenience — with none of the recorded files
 * present, a directory that merely shares a name is not the directory, and nothing is registered. Two
 * candidates that are equally good stay unregistered too, and are reported: `bits/atomicity.h` is in
 * every `config/cpu/<arch>/bits`, and which one this binary compiled against is not something the
 * path says.
 */
class SourceRoot(val root: Path) {
    /** Local directories by last segment — the candidate set for any recorded directory. */
    private val byLastSegment: Map<String, List<Path>> by lazy {
        Files.walk(root).use { paths ->
            paths.asSequence()
                .filter { it.isDirectory() && !it.any { seg -> seg.name == ".git" } }
                .groupBy { it.name }
        }
    }

    fun derive(recorded: Map<String, Set<String>>): RootDerivation {
        val transforms = mutableListOf<DirectoryTransform>()
        val ambiguous = mutableMapOf<String, List<String>>()
        val unmatched = mutableListOf<String>()

        for ((dir, files) in recorded) {
            val segments = dir.split('/').filter { it.isNotEmpty() }
            val byDepth = byLastSegment[segments.lastOrNull()].orEmpty()
                .groupBy { sharedSuffix(segments, it) }
                .filterKeys { it > 0 }
            // Deepest agreement first — but a tier that holds none of the recorded files is not the
            // directory, so fall through to the next. `config/os/mingw32/bits/` agrees on two segments
            // with the installed `mingw32/bits/` and holds neither `atomicity.h` nor `gthr-default.h`;
            // falling through is what lets those be reported as the ambiguity they are — every
            // `config/cpu/<arch>/bits/` has an `atomicity.h` — instead of as simply absent.
            val winners = byDepth.keys.sortedDescending().firstNotNullOfOrNull { depth ->
                byDepth.getValue(depth)
                    .groupBy { candidate -> files.count { File(candidate.toFile(), it).isFile } }
                    .maxByOrNull { it.key }
                    ?.takeIf { (held, _) -> held > 0 }
                    ?.value
            }
            when {
                winners == null -> unmatched += dir
                winners.size > 1 -> ambiguous[dir] = winners.map { it.toString() }.sorted()
                else -> transforms += DirectoryTransform(dir, "${winners.single()}/")
            }
        }
        return RootDerivation(transforms, ambiguous, unmatched)
    }

    /** How many trailing segments [dir] shares with [segments]. */
    private fun sharedSuffix(segments: List<String>, dir: Path): Int {
        val local = dir.map { it.name }
        return segments.reversed().zip(local.reversed()).takeWhile { (a, b) -> a == b }.count()
    }
}

/**
 * Point the program at the sources it was built from: each root becomes directory transforms on the
 * program's [ghidra.program.model.sourcemap.SourcePathTransformer], which persists in program user
 * data and is what Ghidra's own "Source Files and Transforms" dialog edits.
 *
 * The recorded directories come from the program's `SourceFileManager` rather than from our harvest,
 * so this configures the platform from what the platform already holds.
 */
fun Program.applySourceRoots(roots: List<Path>, sink: DiagnosticSink) {
    if (roots.isEmpty()) return
    val recorded = sourceFileManager.allSourceFiles
        .groupBy({ it.path.removeSuffix(it.filename) }, { it.filename })
        .mapValues { (_, files) -> files.toSet() }
    val transformer = UserDataPathTransformer.getPathTransformer(this)

    for (root in roots) {
        val derived = SourceRoot(root).derive(recorded)
        derived.transforms.forEach { transformer.addDirectoryTransform(it.recorded, it.local) }
        sink.log(
            "source-transform-registered",
            "$root: ${derived.transforms.size} directories",
            count = derived.transforms.size.toLong(),
        )
        derived.transforms.forEach { sink.debug("source-transform", "${it.recorded} → ${it.local}") }
        derived.ambiguous.forEach { (dir, candidates) ->
            sink.warn("source-transform-ambiguous", "$dir → ${candidates.size} equal candidates: $candidates")
        }
        // Named, not just counted: what a root failed to account for is how you tell a root that is
        // missing a component from one that is the wrong tree entirely.
        derived.unmatched.forEach { sink.debug("source-transform-unmatched", it) }
    }
}

/**
 * The local file a recorded source maps to, once per run.
 *
 * The transform is a user-data read and the agreement check reads the file, so both are cached; the
 * result is the file to read, or null for a source with no root, no transform, or no agreement.
 */
class LocalSources(
    program: Program,
    private val sink: DiagnosticSink = DummySink,
    private val claims: (GhidraSourceFile) -> List<Claim> = { emptyList() },
) : DiagnosticSink by sink {
    /** A declaration the harvest attributes to a file at a line — what a local file is checked against. */
    data class Claim(val name: String, val line: Int)

    private val transformer = UserDataPathTransformer.getPathTransformer(program)
    private val resolved = mutableMapOf<GhidraSourceFile, File?>()

    operator fun get(source: GhidraSourceFile): File? = resolved.getOrPut(source) {
        transformer.getTransformedPath(source, false)
            ?.let(::File)?.takeIf { it.isFile && it.canRead() }
            ?.takeIf { agrees(source, it) }
    }

    /**
     * Whether the local file is the file the binary was built from.
     *
     * A root for the wrong version resolves happily and lies — same paths, shifted lines — so a mapped
     * file has to earn it: the fraction of the declarations the harvest files here that appear within
     * [SLACK] lines of where it says they are. Per file, never per root, because a project is quite
     * likely to share a root with a stdlib that does not match.
     *
     * [MIN_AGREEMENT] is measured, not guessed. Against gcc 3.2.3 — the version unbouniaf was built
     * with — every file scores 75% or more and most score 100%; against 3.4.6's `bits/` the same files
     * score 54% and below. The two populations do not overlap, and 0.7 sits between them. What still
     * passes from the wrong tree is the handful of headers that did not change in the lines claimed,
     * which is not a false positive: for those, it is the same file.
     */
    private fun agrees(source: GhidraSourceFile, file: File): Boolean {
        val expected = claims(source).filter { it.line > 0 }
        // Too few claims to convict on: `istream.tcc` is attributed one declaration, so a single
        // misfiled name would score it 0% and discard a correctly mapped file. No evidence and not
        // enough evidence are the same verdict — the transform stands.
        if (expected.size < MIN_CLAIMS) return true
        val lines = runCatching { file.readLines() }.getOrElse { return false }
        val found = expected.count { claim ->
            val from = (claim.line - 1 - SLACK).coerceAtLeast(0)
            val to = (claim.line - 1 + SLACK).coerceAtMost(lines.size - 1)
            (from..to).any { claim.name in lines[it] }
        }
        val agreement = found.toDouble() / expected.size
        val scored = "${source.filename} → $file: $found of ${expected.size} declarations on the line claimed"
        if (agreement < MIN_AGREEMENT) {
            warn("source-root-mismatch", scored)
        } else {
            debug("source-root-agrees", scored)
        }
        return agreement >= MIN_AGREEMENT
    }

    private companion object {
        const val SLACK = 2
        const val MIN_CLAIMS = 3
        const val MIN_AGREEMENT = 0.7
    }
}
