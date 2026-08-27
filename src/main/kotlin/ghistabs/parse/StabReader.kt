package ghistabs.parse

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor
import ghistabs.byteProvider

/**
 * Reads stab records from raw record/string bytes, tracking per-CU offsets ([Layout.SECTION]) and
 * merging `\`-continuation chains. Truncated tails (size % 12 ≠ 0) surface via [Result.truncatedTail].
 */
class StabReader(
    private val stab: BinaryReader,
    private val stabStr: (Long) -> String,
    private val layout: Layout = Layout.SECTION,
) {
    /** Where the records came from, which decides how `n_strx` reads and what else shares the table. */
    enum class Layout {
        /** ELF/PE `.stab`: every record is a stab, and an `N_UNDF` header rebases `n_strx` per CU. */
        SECTION,

        /**
         * a.out: the symbol table *is* the stab table. One flat string table, so `n_strx` is absolute,
         * and the debugging symbols ([N_STAB_MASK]) are interleaved with the link-time symbols.
         */
        SYMTAB,
    }

    data class Result(
        val records: List<StabRecord>,
        val totalRecordCount: Int = records.size,
        /** Unprocessed trailing bytes (size % 12 ≠ 0). */
        val truncatedTail: Long = 0,
    )

    constructor(stab: ByteArray, stabStr: ByteArray) : this(
        BinaryReader(
            ByteArrayProvider(stab),
            true,
        ),
        { n ->
            stabStr.asIterable().drop(n.toInt()).takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8)
        },
    )

    fun readAll(monitor: TaskMonitor = TaskMonitor.DUMMY): Result {
        var total = 0
        // Fixed-size records, so the count is the section length — known before reading any of them.
        monitor.initialize(stab.length() / STAB_RECORD_SIZE, "Stabs: reading records")
        val records = mergeContinuations(
            physicalRecords().onEach {
                total++
                monitor.increment()
            },
        )
        return Result(
            records = records,
            totalRecordCount = total,
            truncatedTail = stab.length() - stab.pointerIndex,
        )
    }

    fun readHeader() = StabHeader(
        strx = stab.readNextUnsignedInt().toUInt(),
        type = stab.readNextByte().toUByte(),
        other = stab.readNextByte().toUByte(),
        desc = stab.readNextUnsignedShort().toUShort(),
        value = stab.readNextUnsignedInt().toUInt(),
    )

    /**
     * Every physical record with its `.stabstr` offset and own string resolved — the raw view
     * [readAll] flattens. Continuations are surfaced individually; names keep their trailing `\`.
     * Lazily walks the reader (rewound each iteration), so consuming it advances [stab].
     */
    fun physicalRecords(): Sequence<StabRecord> = sequence {
        stab.pointerIndex = 0
        var cuOff = 0L
        var cuSize = 0L
        var index = 0
        while (stab.hasNext(STAB_RECORD_SIZE)) {
            val record = StabRecord(index++, readHeader())

            // Under SYMTAB the table also holds the link-time symbols; only debugging symbols are ours.
            if (layout == Layout.SYMTAB && (record.raw.type.toInt() and N_STAB_MASK) == 0) continue

            if (layout == Layout.SECTION && record.type == StabType.N_UNDF) {
                cuOff += cuSize
                cuSize = record.value
            }
            record.stabstrOffset = cuOff + record.raw.strx.toLong()
            // strx 0 is a.out's "no name" — gcc uses it for the end-of-function and end-of-source
            // markers. Offset 0 is never a string there: it is the string table's own length field.
            record.name = if (layout == Layout.SYMTAB && record.raw.strx == 0u) "" else stabStr(record.stabstrOffset)
            yield(record)
        }
    }

    /** Blocks holding the records and their strings, and how to read them. */
    data class Source(val records: MemoryBlock, val strings: MemoryBlock, val layout: Layout)

    /**
     * Link-time symbols as name → `n_value`: the half of an a.out symbol table [physicalRecords] skips.
     * An `N_GSYM` carries no address of its own — the format keeps it in the companion link-time symbol
     * — so this is how an a.out global gets placed. Empty under [Layout.SECTION].
     *
     * Consumes the reader (the backing provider cannot seek backwards), so call it on its own instance.
     */
    fun linkSymbols(): Map<String, Long> {
        if (layout != Layout.SYMTAB) return emptyMap()
        stab.pointerIndex = 0
        return buildMap {
            while (stab.hasNext(STAB_RECORD_SIZE)) {
                val raw = readHeader()
                if (raw.type.toInt() and N_STAB_MASK == 0 && raw.strx != 0u) {
                    putIfAbsent(stabStr(raw.strx.toLong()), raw.value.toLong())
                }
            }
        }
    }

    companion object {
        /** Where the formats keep stabs, in precedence order: ELF/PE sections, then the a.out symtab. */
        private val SOURCES = listOf(
            Triple(".stab", ".stabstr", Layout.SECTION),
            Triple(".symtab", ".strtab", Layout.SYMTAB),
        )

        /** Which blocks [program] keeps its stabs in, for callers that need the bytes' addresses. */
        fun sourceOf(program: Program): Source? = SOURCES.firstNotNullOfOrNull { (records, strings, layout) ->
            program.memory.getBlock(records)?.let { r ->
                program.memory.getBlock(strings)?.let { s -> Source(r, s, layout) }
            }
        }

        /**
         * Whether [program] carries stabs at all — block lookups only, opening no streams and reading no
         * bytes. The gate for `canAnalyze` and the menu actions, which must stay cheap and are asked
         * about every program.
         */
        fun hasStabs(program: Program): Boolean = sourceOf(program) != null

        /**
         * [linkSymbols] for [program], on a reader of its own. Empty — and costing only the two block
         * lookups, with no reader built and no streams opened — unless the program is a.out.
         */
        fun linkSymbolsOf(program: Program): Map<String, Long> =
            sourceOf(program)?.takeIf { it.layout == Layout.SYMTAB }
                ?.let { fromProgram(program)?.linkSymbols() }
                .orEmpty()

        fun fromProgram(program: Program): StabReader? = sourceOf(program)?.let { (records, strings, layout) ->
            val littleEndian = !program.memory.isBigEndian
            StabReader(
                stab = BinaryReader(records.byteProvider, littleEndian),
                stabStr = { off: Long -> BinaryReader(strings.byteProvider, littleEndian).readUtf8String(off) },
                layout = layout,
            )
        }
    }
}

val CATEGORY = CategoryPath("/stabs")

/**
 * Get-or-create the `/stabs` Ghidra datatypes on this manager — `resolve` is idempotent under
 * `KEEP_HANDLER`, so this is safe to call repeatedly. Builds the `StabType` 1-byte enum and the
 * 12-byte `StabRecord` layout (single source, mirroring [StabHeader]'s fields), for the .stab overlay.
 */
fun DataTypeManager.stabRecordDataType(): DataType = getDataType(CATEGORY, "StabRecord") ?: run {
    val nType = resolve(
        EnumDataType(CATEGORY, "StabType", 1).apply {
            StabType.entries.filter { it != StabType.UNKNOWN }.forEach { add(it.name, it.code.toLong()) }
        },
        DataTypeConflictHandler.KEEP_HANDLER,
    )
    resolve(
        StructureDataType(CATEGORY, "StabRecord", 0).apply {
            add(DWordDataType.dataType, "n_strx", "index into .stabstr (per-CU)")
            add(nType, "n_type", "stab type code")
            add(ByteDataType.dataType, "n_other", null)
            add(WordDataType.dataType, "n_desc", "line number")
            add(DWordDataType.dataType, "n_value", "address / offset / register (per type)")
        },
        DataTypeConflictHandler.KEEP_HANDLER,
    )
}
