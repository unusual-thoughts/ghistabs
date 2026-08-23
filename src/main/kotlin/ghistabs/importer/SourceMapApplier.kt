package ghistabs.importer

import ghidra.program.model.address.AddressOutOfBoundsException
import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.LineEntry
import ghistabs.materialize.itanium.Itanium

/**
 * Publishes the harvested N_SLINEs as the program's own line map — `SourceFile`s and zero-length
 * `SourceMapEntry`s on its [ghidra.program.model.sourcemap.SourceFileManager] — so address↔line has
 * one writer and the listing, the decompiler and our render all read the same thing.
 *
 * Zero length because an N_SLINE *is* a point: gcc records where a line starts and nothing about
 * where it ends. Deriving a range from the gap to the next entry (what DWARF does) would be an
 * interpretation, and with interleaved inlined code the next entry belongs to a different file half
 * the time. Zero-length entries also never conflict, which the API needs them not to — gcc routinely
 * emits two line numbers at one address.
 *
 * Entries go in under the spelling gcc used and are then folded onto their render identity with
 * `transferSourceMapEntries` (§15), leaving the folded-away spelling listed with no entries.
 *
 * Every source carries `SourceFileIdType.NONE` (what [ghistabs.harvest.sourceFileOf] builds): stabs
 * records no file hash, and hashing the local file would claim provenance we do not have.
 */
class SourceMapApplier(private val ctx: ImportContext<*>, private val index: HarvestIndex) : DiagnosticSink by ctx {
    private val manager = ctx.program.sourceFileManager

    /** How many entries the program holds afterwards, counted from the harvest rather than read back:
     *  the two agreeing is what [ghistabs.StabsImportRegressionBase] asserts. */
    fun apply(): Int {
        val startedAt = System.nanoTime()
        val folds = index.renderIdentityBySource
        val files = folds.keys + folds.values
        for (file in files) manager.addSourceFile(file)

        // Statics carry a decl line no N_SLINE covers — only under -gstabs+, hence the null. Read
        // off the raw harvest, not the render's per-source view: that view resolves attribution, and
        // attribution is decided from the line map this pass is publishing (`Renderer.sources` reads
        // it back), so asking it here is a cycle — it either refuses (`Renderer.declarers`) or
        // answers from an empty map. The line is the emitter's fact about an address; which header
        // the render draws the class in is a later question, and the render still asks it.
        //
        // Generated data is excluded because it has no line of its own to publish ([isGeneratedData]):
        // `_ZTI`/`_ZTS`/`_ZTV` are COMDAT, so every CU naming the class emits one onto a single
        // merged address and dates it from wherever that CU happened to be — `Image::typeinfo` on
        // line 29 of four files, three of which never declared it. The `_ZTI` line does mean the
        // class's declaration, but only once paired with the class's own file, and that pairing is
        // the attribution this pass cannot ask for.
        val staticEntries = index.harvest.staticsByCu.flatMap { (cu, syms) ->
            syms.filterNot { Itanium.isGeneratedData(it.body.name) }.mapNotNull { s ->
                s.line?.let { line -> ctx.resolver.forSymbol(s)?.let { LineEntry(line, it, cu) } }
            }
        }
        val entries = index.harvest.lineEntries.values.flatten() + staticEntries
        publishTextRanges()

        fun identity(entry: LineEntry) = folds[entry.source]?.let { entry.copy(source = it) } ?: entry
        // Grouped by outcome, `""` being published. One warning per reason carrying a per-file
        // breakdown, rather than one per entry: an emitter whose addresses we resolve wrong has every
        // entry rejected, and that would be thousands of bookmarks.
        val byError = entries.groupBy { entry ->
            runCatching {
                manager.addSourceMapEntry(entry.source, entry.line, entry.addr, 0)
            }.exceptionOrNull()?.let {
                // gcc's N_SLINE value is function-relative on PE/COFF; a function whose start we resolved
                // wrong, or one in a section the loader left out, lands outside every block.
                when (it) {
                    is AddressOutOfBoundsException -> "sourcemap-entry-unmapped"
                    is IllegalArgumentException -> "sourcemap-entry-rejected"
                    else -> "sourcemap-error-${it.javaClass.name}"
                }
            }
        }
        for ((reason, bad) in byError) {
            if (reason != null) {
                warn(reason, "dropped ${bad.groupingBy {it.source.filename}.eachCount()}", count = bad.size.toLong())
            }
        }

        val dropped = byError.filterKeys { it != null }.values.flatten().mapTo(mutableSetOf(), ::identity)

        // A duplicate that disappears is a content change, so it is counted rather than absorbed: the
        // manager silently returns the existing entry for a repeated (file, line, address, length),
        // and the fold makes more of them by merging two spellings onto one identity.
        val published = entries.mapTo(mutableSetOf(), ::identity).also { it -= dropped }

        for ((raw, target) in folds) if (raw != target) manager.transferSourceMapEntries(raw, target)

        debug("sourcemap-files", count = files.size.toLong())
        debug("sourcemap-folded-files", count = folds.count { (raw, target) -> raw != target }.toLong())
        debug("sourcemap-duplicate-entries", count = (entries.size - published.size - dropped.size).toLong())
        // Message carries the wall time — a DB write per N_SLINE is the one part of this that could
        // grow into something worth an option, and a counter holding a duration would be baseline noise.
        debug(
            "sourcemap-entries",
            "${published.size} entries over ${files.size} files in ${(System.nanoTime() - startedAt) / 1_000_000} ms",
            count = published.size.toLong(),
        )
        return published.size
    }

    /**
     * The N_SO/N_SOL partition as ranged entries — gcc's own statement of which file each run of text
     * came from, which nothing else in the import records.
     *
     * Line 0 because neither record carries one (gcc hardcodes `desc` to 0 for both), and Ghidra
     * accepts it — only a negative line is refused. The ranges are disjoint by construction, which
     * `SourceMapEntry` requires of any two entries with non-zero length that intersect; the
     * zero-length N_SLINE entries are explicitly allowed to sit inside them.
     */
    private fun publishTextRanges() {
        val ranges = index.harvest.textRanges.ifEmpty { return }
        for (file in ranges.values.toSet()) manager.addSourceFile(file)
        val failed = ranges.entries.groupingBy { (range, source) ->
            runCatching { manager.addSourceMapEntry(source, 0, range.minAddress, range.length) }
                .exceptionOrNull()?.javaClass?.simpleName
        }.eachCount()
        for ((reason, n) in failed) {
            if (reason != null) warn("textrange-rejected", reason, count = n.toLong())
        }
        debug("textrange-entries", count = (failed[null] ?: 0).toLong())
    }
}
