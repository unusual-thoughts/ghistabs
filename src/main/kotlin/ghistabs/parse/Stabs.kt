package ghistabs.parse

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DWordDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.EnumDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.WordDataType
import ghidra.program.model.listing.Program
import ghistabs.byteProvider
import kotlinx.serialization.Serializable

/** On-disk size of a single stab record (Sun a.out / PE-COFF / ELF). */
const val STAB_RECORD_SIZE: Int = 12

/**
 * Stab record type codes, mirrored from `binutils/include/aout/stab.def`.
 * Includes Apple ld / Sun cross-toolchain codes so the parser doesn't fall into UNKNOWN on them.
 */
enum class StabType(val code: UByte) {
    UNKNOWN(0xFFu),

    /**
     * CU header (Solaris2 / ELF stabs-in-sections). `n_value`=stabstr size for this CU,
     * `n_strx`=source filename, `n_desc`=count of upcoming symbols.
     */
    N_UNDF(0x00u),

    /** Global variable. Only the name is significant; address is in the corresponding external symbol. */
    N_GSYM(0x20u),

    /** Function name (for BSD Fortran). Only the name is significant; address is in the external symbol. */
    N_FNAME(0x22u),

    /**
     * Function name / text-segment variable. Value=start address.
     * Empty-name `N_FUN` marks function *end* (value=end address); otherwise function ends at next `N_FUN`.
     */
    N_FUN(0x24u),

    /** Data-segment variable with internal linkage ("static sym"). Value is its address. */
    N_STSYM(0x26u),

    /** BSS-segment variable with internal linkage (`.lcomm`). Value is its address. */
    N_LCSYM(0x28u),

    /** Name of main routine. Only the name is significant. Not used in C. */
    N_MAIN(0x2Au),

    /** Read-only data symbol in `.rodata` section (Solaris2). */
    N_ROSYM(0x2Cu),

    /** Beginning of a relocatable function block, including stabs (macOS / Apple). */
    N_BNSYM(0x2Eu),

    /** Global symbol for Pascal. Value is supposedly the line number. */
    N_PC(0x30u),

    /** Number of symbols: `0, files,,funcs,lines` (Ultrix V4.0). */
    N_NSYMS(0x32u),

    /** No DST map for symbol — variable may have been optimized out (Ultrix V4.0). */
    N_NOMAP(0x34u),

    /**
     * `#define` body (GNU `-g3 -gstabs`). String=`"name body"`, `desc`=line number.
     * Documented in stabs.texinfo but absent from `stab.def`.
     */
    N_MAC_DEFINE(0x36u),

    /** Object file path (Solaris2 `.stab.index`). Two in a row give build dir + relative `.o` path. */
    N_OBJ(0x38u),

    /** `#undef` (GNU `-g3 -gstabs`). String=name, `desc`=line. Absent from `stab.def`. */
    N_MAC_UNDEF(0x3Au),

    /** Debugger options (Solaris2). Also emitted by Apple/GCC with `gcc2_compiled.`. */
    N_OPT(0x3Cu),

    /** Register variable. Value is the register number. */
    N_RSYM(0x40u),

    /** Modula-2 compilation unit. */
    N_M2C(0x42u),

    /** Line number in text segment. `desc` is the line number; value is the corresponding address. */
    N_SLINE(0x44u),

    /** Line number in data segment. GCC2 uses the variable's own stab `desc` instead; gdb ignores since 3.5. */
    N_DSLINE(0x46u),

    /** Line number in BSS segment. Aliases `N_BROWS` (Sun source browser `.cb` path). */
    N_BSLINE(0x48u),

    /** GNU Modula-2 definition module dependency. Value is the modification time of the definition file. */
    N_DEFD(0x4Au),

    /** Function start/body/end line numbers (Solaris2). */
    N_FLINE(0x4Cu),

    /** End of a relocatable function block + debugging info (macOS / Apple). */
    N_ENSYM(0x4Eu),

    /** GNU C++ exception variable. Aliases `N_MOD2` (Ultrix V4.0 Modula-2). */
    N_EHDECL(0x50u),

    /** GNU C++ `catch` clause. `desc == 0` = catches all; non-zero = `CAUGHT` stabs follow. */
    N_CATCH(0x54u),

    /** Structure or union element. Value is the offset within the structure. */
    N_SSYM(0x60u),

    /** Last stab emitted for module (Solaris2). */
    N_ENDM(0x62u),

    /**
     * Main source file path. Value=start text address. If two appear, the one ending in `/` is build dir,
     * the other is source file. Empty-name `N_SO` marks file end (value=end of text).
     * `desc` language: 0x1=ASM, 0x2=K&R C, 0x3=ANSI C, 0x4=C++, 0x5=Fortran, 0x6=Pascal,
     * 0x7=Fortran90, 0x32=ObjC, 0x33=ObjC++.
     */
    N_SO(0x64u),

    /** Apple `.o` association after `N_SO`. String=`.o` filename, value=`st_mtime`. */
    N_OSO(0x66u),

    /** Name of an alias symbol (SunPro Fortran 77). */
    N_ALIAS(0x6Cu),

    /** Automatic (stack) variable; value is offset from frame pointer. Also used for type descriptions. */
    N_LSYM(0x80u),

    /**
     * Include-file start (Sun). Linker fills `value` with a checksum of header stabs,
     * matched against `N_EXCL` for duplicate-include suppression.
     */
    N_BINCL(0x82u),

    /** `#include`d sub-source filename. Value=start text address; used for line-number tracking only. */
    N_SOL(0x84u),

    /** Compiler parameters (Apple/Mach-O). String is the parameter name; other fields are zero. */
    N_PARAMS(0x86u),

    /** Compiler version string (Apple/Mach-O). String is the version; other fields are zero. */
    N_VERSION(0x88u),

    /** Compiler `-O` optimization level (Apple/Mach-O). String is the level; other fields are zero. */
    N_OLEVEL(0x8Au),

    /** Parameter variable. Value is offset from the argument pointer. */
    N_PSYM(0xA0u),

    /** Include-file end. Brackets `N_BINCL`; pairs can nest. */
    N_EINCL(0xA2u),

    /** Alternate entry point. AIX/XCOFF `C_ENTRY` — only name is significant. */
    N_ENTRY(0xA4u),

    /**
     * Lexical block start. `desc`=nesting level; value=start address (relative to source file usually,
     * relative to enclosing function in stabs-in-sections). Variables in the block *precede* this stab.
     */
    N_LBRAC(0xC0u),

    /**
     * Placeholder replacing a duplicate `N_BINCL`/`N_EINCL` pair (Sun linker output).
     * Value=original `N_BINCL` checksum, matched by filename.
     */
    N_EXCL(0xC2u),

    /** Modula-2 scope information (Sun linker). */
    N_SCOPE(0xC4u),

    /** Patch Run Time Checker marker (Solaris2). */
    N_PATCH(0xD0u),

    /** Lexical block end. `desc` matches `N_LBRAC`; value=end address (same relativity). */
    N_RBRAC(0xE0u),

    /** Begin named common block. */
    N_BCOMM(0xE2u),

    /** End named common block (name matches `N_BCOMM`). */
    N_ECOMM(0xE4u),

    /** Common-block member; value=offset within block. Appears between `N_BCOMM`/`N_ECOMM`. */
    N_ECOML(0xE8u),

    /** Pascal `with`-statement scope: `type,,0,0,offset` (Solaris2). */
    N_WITH(0xEAu),

    /** Gould non-base register symbol (text). */
    N_NBTEXT(0xF0u),

    /** Gould non-base register symbol (data). */
    N_NBDATA(0xF2u),

    /** Gould non-base register symbol (BSS). */
    N_NBBSS(0xF4u),

    /** Gould non-base register symbol (static). */
    N_NBSTS(0xF6u),

    /** Gould non-base register symbol (local common). */
    N_NBLCS(0xF8u),

    /** Length-value entry for the preceding stab. */
    N_LENG(0xFEu),
    ;

    companion object {
        private val byCode: Map<UByte, StabType> = entries.filter { it != UNKNOWN }.associateBy { it.code }

        fun fromCode(b: UByte): StabType = byCode[b] ?: UNKNOWN
    }
}

/** Mnemonics that may carry a `\`-continuation tail. */
val TYPES_WITH_CONTINUATION: Set<StabType> = setOf(
    StabType.N_GSYM,
    StabType.N_FUN,
    StabType.N_STSYM,
    StabType.N_LCSYM,
    StabType.N_RSYM,
    StabType.N_LSYM,
    StabType.N_PSYM,
)

/**
 * One assembled stab record — `name` has been resolved through `.stabstr` (per-CU offset applied)
 * and any `\`-continuation chain merged. `index` is the first physical record's file-order index
 * (its byte position is `index * `[STAB_RECORD_SIZE]); absorbed continuations are not surfaced.
 * [stabstrOffset] is the resolved absolute `.stabstr` offset of this record's own name — overlay
 * metadata set during the physical read, not part of the serialized value.
 */
@Serializable
data class StabRecord(val index: Int, val type: StabType, val raw: RawHeader, var name: String = "") {
    internal constructor(index: Int, raw: RawHeader) : this(
        index,
        type = StabType.fromCode(raw.type),
        raw = raw,
    )

    internal constructor(
        index: Int,
        type: StabType,
        other: Int,
        desc: Int,
        value: Long,
        name: String,
    ) : this(index, type, raw = RawHeader(0u, type.code, other.toUByte(), desc.toUShort(), value.toUInt()), name)

    // Semantic view: RawHeader is faithfully unsigned/on-disk-width; the harvester wants
    // ergonomic signed types for address/offset math, so widen here.
    val rawType get() = raw.type
    val value get() = raw.value.toLong()
    val desc get() = raw.desc.toInt()
    val other get() = raw.other

    var stabstrOffset: Long = 0
}

/**
 * Reads stab records from raw `.stab` / `.stabstr` bytes, tracking per-CU offsets and merging
 * `\`-continuation chains. Truncated tails (size % 12 ≠ 0) are surfaced via [Result.truncatedTail].
 */
class StabReader(private val stab: BinaryReader, private val stabStr: (Long) -> String) {
    data class Result(
        val records: List<StabRecord>,
        val totalRecordCount: Int = records.size,
        /** Unprocessed trailing bytes (size % 12 ≠ 0). */
        val truncatedTail: Long = 0,
    )

    constructor(stab: ByteArray, stabStr: ByteArray) : this(
        BinaryReader(
            ByteArrayProvider(
                stab,
            ),
            true,
        ),
        { n ->
            stabStr.asIterable().drop(n.toInt()).takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8)
        },
    )

    fun readAll(): Result {
        var total = 0
        val records = mergeContinuations(physicalRecords().onEach { total++ })
        return Result(
            records = records,
            totalRecordCount = total,
            truncatedTail = stab.length() - stab.pointerIndex,
        )
    }

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
            val record = StabRecord(index++, RawHeader(stab))

            if (record.type == StabType.N_UNDF) {
                cuOff += cuSize
                cuSize = record.value
            }
            record.stabstrOffset = cuOff + record.raw.strx.toLong()
            record.name = stabStr(record.stabstrOffset)
            yield(record)
        }
    }

    companion object {
        /** Read `.stab`/`.stabstr` from [program]. Returns null if either block is missing. */
        fun fromProgram(program: Program): StabReader? {
            val mem = program.memory
            val stabBlock = mem.getBlock(".stab") ?: return null
            val stabstrBlock = mem.getBlock(".stabstr") ?: return null
            val littleEndian = !program.memory.isBigEndian

            return StabReader(
                stab = BinaryReader(stabBlock.byteProvider, littleEndian),
                stabStr = { off: Long -> BinaryReader(stabstrBlock.byteProvider, littleEndian).readUtf8String(off) },
            )
        }
    }
}

/**
 * Fold `\`-continuation chains over the [StabReader.physicalRecords] stream (the pure assembly step
 * `readAll` used to do inline). A continuation's tail records share the starter's type and each end
 * with `\` until the last; the merged record keeps the starter's index and header. A single forward
 * pass carrying the still-`open` group needs no lookahead. Every other record, `N_UNDF` headers
 * included, passes through untouched.
 */
internal fun mergeContinuations(physical: Sequence<StabRecord>): List<StabRecord> = buildList {
    var open: StabRecord? = null
    for (rec in physical) {
        if (open != null && rec.type == open.type) {
            // Continuation: fold into the starter already in the list, don't emit it.
            open.name += rec.name.removeSuffix("\\")
            if (!rec.name.endsWith("\\")) open = null
        } else {
            val starter = rec.type in TYPES_WITH_CONTINUATION && rec.name.endsWith("\\")
            if (starter) rec.name = rec.name.dropLast(1)
            open = rec.takeIf { starter }
            add(rec)
        }
    }
}

private val CATEGORY = CategoryPath("/stabs")

/** Raw stab header, before type interpretation — the on-disk 12 bytes, faithfully unsigned. */
@Serializable
data class RawHeader(val strx: UInt, val type: UByte, val other: UByte, val desc: UShort, val value: UInt) {
    constructor(reader: BinaryReader) : this(
        strx = reader.readNextUnsignedInt().toUInt(),
        type = reader.readNextByte().toUByte(),
        other = reader.readNextByte().toUByte(),
        desc = reader.readNextUnsignedShort().toUShort(),
        value = reader.readNextUnsignedInt().toUInt(),
    )
}

/**
 * Get-or-create the `/stabs` Ghidra datatypes on this manager — `resolve` is idempotent under
 * `KEEP_HANDLER`, so this is safe to call repeatedly. Builds the `StabType` 1-byte enum and the
 * 12-byte `StabRecord` layout (single source, mirroring [RawHeader]'s fields), for the .stab overlay.
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
