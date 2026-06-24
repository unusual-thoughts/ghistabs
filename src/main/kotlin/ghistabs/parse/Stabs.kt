package ghistabs.parse

import ghidra.program.model.listing.Program
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** On-disk size of a single stab record (Sun a.out / PE-COFF / ELF). */
const val STAB_RECORD_SIZE: Int = 12

/**
 * Stab record type codes, mirrored from `binutils/include/aout/stab.def`.
 * Includes Apple ld / Sun cross-toolchain codes so the parser doesn't fall into UNKNOWN on them.
 */
enum class StabType(val code: Int) {
    UNKNOWN(-1),

    /**
     * CU header (Solaris2 / ELF stabs-in-sections). `n_value`=stabstr size for this CU,
     * `n_strx`=source filename, `n_desc`=count of upcoming symbols.
     */
    N_UNDF(0x00),

    /** Global variable. Only the name is significant; address is in the corresponding external symbol. */
    N_GSYM(0x20),

    /** Function name (for BSD Fortran). Only the name is significant; address is in the external symbol. */
    N_FNAME(0x22),

    /**
     * Function name / text-segment variable. Value=start address.
     * Empty-name `N_FUN` marks function *end* (value=end address); otherwise function ends at next `N_FUN`.
     */
    N_FUN(0x24),

    /** Data-segment variable with internal linkage ("static sym"). Value is its address. */
    N_STSYM(0x26),

    /** BSS-segment variable with internal linkage (`.lcomm`). Value is its address. */
    N_LCSYM(0x28),

    /** Name of main routine. Only the name is significant. Not used in C. */
    N_MAIN(0x2A),

    /** Read-only data symbol in `.rodata` section (Solaris2). */
    N_ROSYM(0x2C),

    /** Beginning of a relocatable function block, including stabs (macOS / Apple). */
    N_BNSYM(0x2E),

    /** Global symbol for Pascal. Value is supposedly the line number. */
    N_PC(0x30),

    /** Number of symbols: `0, files,,funcs,lines` (Ultrix V4.0). */
    N_NSYMS(0x32),

    /** No DST map for symbol — variable may have been optimized out (Ultrix V4.0). */
    N_NOMAP(0x34),

    /**
     * `#define` body (GNU `-g3 -gstabs`). String=`"name body"`, `desc`=line number.
     * Documented in stabs.texinfo but absent from `stab.def`.
     */
    N_MAC_DEFINE(0x36),

    /** Object file path (Solaris2 `.stab.index`). Two in a row give build dir + relative `.o` path. */
    N_OBJ(0x38),

    /** `#undef` (GNU `-g3 -gstabs`). String=name, `desc`=line. Absent from `stab.def`. */
    N_MAC_UNDEF(0x3A),

    /** Debugger options (Solaris2). Also emitted by Apple/GCC with `gcc2_compiled.`. */
    N_OPT(0x3C),

    /** Register variable. Value is the register number. */
    N_RSYM(0x40),

    /** Modula-2 compilation unit. */
    N_M2C(0x42),

    /** Line number in text segment. `desc` is the line number; value is the corresponding address. */
    N_SLINE(0x44),

    /** Line number in data segment. GCC2 uses the variable's own stab `desc` instead; gdb ignores since 3.5. */
    N_DSLINE(0x46),

    /** Line number in BSS segment. Aliases `N_BROWS` (Sun source browser `.cb` path). */
    N_BSLINE(0x48),

    /** GNU Modula-2 definition module dependency. Value is the modification time of the definition file. */
    N_DEFD(0x4A),

    /** Function start/body/end line numbers (Solaris2). */
    N_FLINE(0x4C),

    /** End of a relocatable function block + debugging info (macOS / Apple). */
    N_ENSYM(0x4E),

    /** GNU C++ exception variable. Aliases `N_MOD2` (Ultrix V4.0 Modula-2). */
    N_EHDECL(0x50),

    /** GNU C++ `catch` clause. `desc == 0` = catches all; non-zero = `CAUGHT` stabs follow. */
    N_CATCH(0x54),

    /** Structure or union element. Value is the offset within the structure. */
    N_SSYM(0x60),

    /** Last stab emitted for module (Solaris2). */
    N_ENDM(0x62),

    /**
     * Main source file path. Value=start text address. If two appear, the one ending in `/` is build dir,
     * the other is source file. Empty-name `N_SO` marks file end (value=end of text).
     * `desc` language: 0x1=ASM, 0x2=K&R C, 0x3=ANSI C, 0x4=C++, 0x5=Fortran, 0x6=Pascal,
     * 0x7=Fortran90, 0x32=ObjC, 0x33=ObjC++.
     */
    N_SO(0x64),

    /** Apple `.o` association after `N_SO`. String=`.o` filename, value=`st_mtime`. */
    N_OSO(0x66),

    /** Name of an alias symbol (SunPro Fortran 77). */
    N_ALIAS(0x6C),

    /** Automatic (stack) variable; value is offset from frame pointer. Also used for type descriptions. */
    N_LSYM(0x80),

    /**
     * Include-file start (Sun). Linker fills `value` with a checksum of header stabs,
     * matched against `N_EXCL` for duplicate-include suppression.
     */
    N_BINCL(0x82),

    /** `#include`d sub-source filename. Value=start text address; used for line-number tracking only. */
    N_SOL(0x84),

    /** Compiler parameters (Apple/Mach-O). String is the parameter name; other fields are zero. */
    N_PARAMS(0x86),

    /** Compiler version string (Apple/Mach-O). String is the version; other fields are zero. */
    N_VERSION(0x88),

    /** Compiler `-O` optimization level (Apple/Mach-O). String is the level; other fields are zero. */
    N_OLEVEL(0x8A),

    /** Parameter variable. Value is offset from the argument pointer. */
    N_PSYM(0xA0),

    /** Include-file end. Brackets `N_BINCL`; pairs can nest. */
    N_EINCL(0xA2),

    /** Alternate entry point. AIX/XCOFF `C_ENTRY` — only name is significant. */
    N_ENTRY(0xA4),

    /**
     * Lexical block start. `desc`=nesting level; value=start address (relative to source file usually,
     * relative to enclosing function in stabs-in-sections). Variables in the block *precede* this stab.
     */
    N_LBRAC(0xC0),

    /**
     * Placeholder replacing a duplicate `N_BINCL`/`N_EINCL` pair (Sun linker output).
     * Value=original `N_BINCL` checksum, matched by filename.
     */
    N_EXCL(0xC2),

    /** Modula-2 scope information (Sun linker). */
    N_SCOPE(0xC4),

    /** Patch Run Time Checker marker (Solaris2). */
    N_PATCH(0xD0),

    /** Lexical block end. `desc` matches `N_LBRAC`; value=end address (same relativity). */
    N_RBRAC(0xE0),

    /** Begin named common block. */
    N_BCOMM(0xE2),

    /** End named common block (name matches `N_BCOMM`). */
    N_ECOMM(0xE4),

    /** Common-block member; value=offset within block. Appears between `N_BCOMM`/`N_ECOMM`. */
    N_ECOML(0xE8),

    /** Pascal `with`-statement scope: `type,,0,0,offset` (Solaris2). */
    N_WITH(0xEA),

    // Gould non-base register symbols. GNU assigned these values without a Gould to verify against.
    /** Gould non-base register symbol (text). */
    N_NBTEXT(0xF0),

    /** Gould non-base register symbol (data). */
    N_NBDATA(0xF2),

    /** Gould non-base register symbol (BSS). */
    N_NBBSS(0xF4),

    /** Gould non-base register symbol (static). */
    N_NBSTS(0xF6),

    /** Gould non-base register symbol (local common). */
    N_NBLCS(0xF8),

    /** Length-value entry for the preceding stab. */
    N_LENG(0xFE),
    ;

    companion object {
        private val byCode: Map<Int, StabType> = entries.filter { it != UNKNOWN }.associateBy { it.code }

        fun fromCode(b: Int): StabType = byCode[b and 0xFF] ?: UNKNOWN
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
 * and any `\`-continuation chain merged. `recordIndex` is the first physical record's index;
 * absorbed continuations are not surfaced.
 */
@Serializable
data class StabRecord(
    val recordIndex: Int,
    val type: StabType,
    val rawType: Int,
    val other: Int,
    val desc: Int,
    val value: Long,
    val name: String,
)

/**
 * Reads stab records from raw `.stab` / `.stabstr` bytes, tracking per-CU offsets and merging
 * `\`-continuation chains. Truncated tails (size % 12 ≠ 0) are surfaced via [Result.truncatedTail].
 */
class StabReader(
    private val stab: ByteArray,
    private val stabstr: ByteArray,
    private val littleEndian: Boolean = true,
) {
    data class Result(
        val records: List<StabRecord>,
        val recordCount: Int,
        /** Unprocessed trailing bytes (size % 12 ≠ 0). */
        val truncatedTail: Int,
    ) {
        constructor(records: List<StabRecord>) : this(records, records.size, 0)
    }

    fun readAll(): Result {
        val records = mutableListOf<StabRecord>()
        val buf = ByteBuffer.wrap(stab).apply {
            order(if (littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        }

        var cuOff = 0
        var cuSize = 0
        var physicalIndex = 0

        while (buf.remaining() >= STAB_RECORD_SIZE) {
            val recordIndex = physicalIndex
            val header = decodeRecord(buf)
            val (nStrx, nType, nOther, nDesc, nValue) = header
            physicalIndex++

            val type = StabType.fromCode(nType)

            if (type == StabType.N_UNDF) {
                cuOff += cuSize
                cuSize = nValue.toInt()
                records.add(
                    StabRecord(
                        recordIndex = recordIndex,
                        type = type,
                        rawType = nType,
                        other = nOther,
                        desc = nDesc,
                        value = nValue,
                        name = "",
                    ),
                )
                continue
            }

            val cuEnd = if (cuSize > 0) cuOff + cuSize else stabstr.size
            var name = cstring(stabstr, cuOff + nStrx, cuEnd)

            if (type in TYPES_WITH_CONTINUATION && name.endsWith("\\")) {
                name = name.dropLast(1)

                // Spec says continuation records carry 0 in non-string fields; trusted, not asserted.
                while (buf.remaining() >= STAB_RECORD_SIZE) {
                    val peekPos = buf.position()
                    val contHeader = decodeRecord(buf)

                    if (StabType.fromCode(contHeader.type) != type) {
                        buf.position(peekPos)
                        break
                    }

                    val contName = cstring(stabstr, cuOff + contHeader.strx, cuEnd)
                    name += if (contName.endsWith("\\")) {
                        contName.dropLast(1)
                    } else {
                        contName
                    }
                    physicalIndex++

                    if (!contName.endsWith("\\")) {
                        break
                    }
                }
            }

            records.add(
                StabRecord(
                    recordIndex = recordIndex,
                    type = type,
                    rawType = nType,
                    other = nOther,
                    desc = nDesc,
                    value = nValue,
                    name = name,
                ),
            )
        }

        val truncatedTail = buf.remaining()

        return Result(
            records = records,
            recordCount = physicalIndex,
            truncatedTail = truncatedTail,
        )
    }

    private fun decodeRecord(buf: ByteBuffer) = RawHeader(
        strx = buf.int,
        type = buf.get().toInt() and 0xFF,
        other = buf.get().toInt() and 0xFF,
        desc = buf.short.toInt() and 0xFFFF,
        value = buf.int.toLong(),
    )

    private fun cstring(bytes: ByteArray, start: Int, endExclusive: Int): String {
        if (start !in 0 until endExclusive) {
            return ""
        }
        var idx = start
        while (idx < endExclusive && bytes[idx] != 0.toByte()) {
            idx++
        }
        val len = idx - start
        return if (len > 0) String(bytes, start, len, Charsets.UTF_8) else ""
    }

    companion object {
        /** Read `.stab`/`.stabstr` from [program]. Returns null if either block is missing. */
        fun fromProgram(program: Program): Result? {
            val mem = program.memory
            val stabBlock = mem.getBlock(".stab") ?: return null
            val stabstrBlock = mem.getBlock(".stabstr") ?: return null
            val stab = ByteArray(stabBlock.size.toInt())
            val stabstr = ByteArray(stabstrBlock.size.toInt())
            stabBlock.getBytes(stabBlock.start, stab)
            stabstrBlock.getBytes(stabstrBlock.start, stabstr)
            val littleEndian = !program.memory.isBigEndian
            return StabReader(stab, stabstr, littleEndian).readAll()
        }
    }
}

/** Raw stab header, before type interpretation. */
private data class RawHeader(val strx: Int, val type: Int, val other: Int, val desc: Int, val value: Long)
