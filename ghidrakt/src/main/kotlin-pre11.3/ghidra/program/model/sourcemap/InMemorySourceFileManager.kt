package ghidra.program.model.sourcemap

import ghidra.program.database.sourcemap.SourceFile
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.listing.Program
import java.util.WeakHashMap

/**
 * The line map, held in memory instead of in the program database.
 *
 * Below 11.3 the program has nowhere to persist a source map, but the render reads its lines back
 * through this same interface — so storing them is what keeps the line-aligned skeleton working. What
 * is lost is only persistence and the listing/decompiler integration, not the render.
 */
class InMemorySourceFileManager : SourceFileManager {
    private val files = LinkedHashSet<SourceFile>()

    // A set, because the manager is specified to return the existing entry for a repeated
    // (file, line, address, length) rather than store it twice — which the §15 fold relies on.
    private val entries = LinkedHashSet<Entry>()

    private data class Entry(val line: Int, val file: SourceFile, val addr: Address, val len: Long) :
        SourceMapEntry {
        override fun getLineNumber() = line

        override fun getSourceFile() = file

        override fun getBaseAddress() = addr

        override fun getLength() = len

        /** Null at length 0, per the interface's contract — and every entry we publish is a point. */
        override fun getRange(): AddressRange? = null

        override fun compareTo(other: SourceMapEntry) = COMPARATOR.compare(this, other)

        private companion object {
            val COMPARATOR = compareBy<SourceMapEntry>(
                { it.sourceFile },
                { it.lineNumber },
                { it.baseAddress },
                { it.length },
            )
        }
    }

    override fun addSourceFile(sourceFile: SourceFile) = files.add(sourceFile)

    override fun addSourceMapEntry(
        sourceFile: SourceFile,
        lineNumber: Int,
        baseAddr: Address,
        length: Long,
    ): SourceMapEntry = Entry(lineNumber, sourceFile, baseAddr, length)
        .also {
            files.add(sourceFile)
            entries.add(it)
        }

    override fun transferSourceMapEntries(source: SourceFile, target: SourceFile) {
        val moved = entries.filter { it.file == source }
        entries -= moved.toSet()
        entries += moved.map { it.copy(file = target) }
        files.add(target)
    }

    override fun getAllSourceFiles() = files.toList()

    override fun getMappedSourceFiles() = entries.map { it.file }.distinct()

    override fun getSourceMapEntries(sourceFile: SourceFile): List<SourceMapEntry> =
        entries.filter { it.file == sourceFile }.sorted()

    override fun getSourceMapEntries(address: Address): List<SourceMapEntry> = entries.filter { it.addr == address }

    override fun getSourceMapEntryIterator(address: Address, forward: Boolean): List<SourceMapEntry> =
        entries.filter { if (forward) it.addr >= address else it.addr <= address }
            .sortedWith(compareBy { it.addr })
            .let { if (forward) it else it.asReversed() }

    companion object {
        private val byProgram = WeakHashMap<Program, SourceFileManager>()

        /** One manager per program, so the import writes where the render reads. */
        fun of(program: Program): SourceFileManager =
            synchronized(byProgram) { byProgram.getOrPut(program) { InMemorySourceFileManager() } }
    }
}
