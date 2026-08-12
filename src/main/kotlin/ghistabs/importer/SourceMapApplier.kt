package ghistabs.importer

import ghidra.program.model.address.AddressOutOfBoundsException
import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.LineEntry

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

        val entries = index.harvest.lineEntries.values.flatten()
        fun identity(entry: LineEntry) = Triple(folds[entry.source], entry.line, entry.addr)
        // Grouped by outcome, `""` being published. One warning per reason carrying a per-file
        // breakdown, rather than one per entry: an emitter whose addresses we resolve wrong has every
        // entry rejected, and that would be thousands of bookmarks.
        val dropped = entries.groupBy(::publish)
            .filterKeys { it.isNotEmpty() }
            .onEach { (reason, bad) ->
                warn(reason, "dropped ${bad.groupingBy { it.source.filename }.eachCount()}", count = bad.size.toLong())
            }
            .values.flatten().mapTo(mutableSetOf(), ::identity)
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

    /** The counter [entry] failed under, or `""` when it was published. */
    private fun publish(entry: LineEntry): String = try {
        manager.addSourceMapEntry(entry.source, entry.line, entry.addr, 0)
        ""
    } catch (e: AddressOutOfBoundsException) {
        // gcc's N_SLINE value is function-relative on PE/COFF; a function whose start we resolved
        // wrong, or one in a section the loader left out, lands outside every block.
        "sourcemap-entry-unmapped"
    } catch (e: IllegalArgumentException) {
        "sourcemap-entry-rejected"
    }
}
