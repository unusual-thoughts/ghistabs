package ghistabs.parser

import ghidra.program.model.listing.Program
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * On-disk size in bytes of a single stab record (Sun a.out / PE-COFF / ELF).
 * Independent of host endianness.
 */
const val STAB_RECORD_SIZE: Int = 12

/**
 * STABS record type codes (mirrored from `binutils/include/aout/stab.def`).
 * Coverage targets the standard gdb/gcc/Sun set; codes used by Apple ld
 * (N_BNSYM/N_ENSYM/N_OBJ/N_ALIAS), Sun Pascal/Fortran (N_NSYMS/N_NOMAP/
 * N_PATCH/N_WITH/N_NBTEXT…), and Sun read-only data (N_ROSYM) are included
 * so the parser doesn't fall into UNKNOWN on cross-toolchain binaries.
 */
enum class StabType(val code: Int) {
    /** Unknown or unrecognized stab type */
    UNKNOWN(-1),

    /**
     * Compilation unit header (Solaris2 / ELF stabs-in-sections).
     * `n_value` gives the size of the string section for this CU;
     * `n_strx` gives the source filename; `n_desc` gives the count of
     * upcoming symbols for this file.
     */
    N_UNDF(0x00),

    /** Global variable. Only the name is significant; address is in the corresponding external symbol. */
    N_GSYM(0x20),

    /** Function name (for BSD Fortran). Only the name is significant; address is in the external symbol. */
    N_FNAME(0x22),

    /**
     * Function name or text-segment variable for C. Value is the function's start address.
     * An `N_FUN` with an **empty name** marks the *end* of a function; its value is the end address.
     * Without such a closing entry, the function is assumed to end at the next `N_FUN` or end of text.
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
     * Name and body of a `#define`d macro (GNU extension, emitted with `-g3 -gstabs`).
     * String field is `"macro-name macro-body"`; `desc` is the line number of the `#define`.
     * Note: present in the stabs documentation but absent from `stab.def`.
     */
    N_MAC_DEFINE(0x36),

    /**
     * Object file path (Solaris2). Like `N_SO` but for the `.o` file.
     * Two in a row give the build directory and the relative `.o` path.
     * Used with `.stab.index` so the debugger reads real stabs from the `.o` directly.
     */
    N_OBJ(0x38),

    /**
     * Name of an `#undef`ed macro (GNU extension, emitted with `-g3 -gstabs`).
     * String field is just `"macro-name"`; `desc` is the line number of the `#undef`.
     * Note: present in the stabs documentation but absent from `stab.def`.
     */
    N_MAC_UNDEF(0x3A),

    /**
     * Debugger options for this module (Solaris2).
     * Records source-language settings, e.g. ANSI vs traditional integral promotions.
     * Also emitted by Apple/GCC with `gcc2_compiled.`
     */
    N_OPT(0x3C),

    /** Register variable. Value is the register number. */
    N_RSYM(0x40),

    /** Modula-2 compilation unit. */
    N_M2C(0x42),

    /** Line number in text segment. `desc` is the line number; value is the corresponding address. */
    N_SLINE(0x44),

    /**
     * Line number in data segment. Intended to describe the source location of a variable
     * declaration, but GCC2 uses the variable's own stab `desc` field instead.
     * GDB has ignored these since at least version 3.5.
     */
    N_DSLINE(0x46),

    /**
     * Line number in BSS segment. Same caveat as `N_DSLINE` — rarely used in practice.
     * Alias `N_BROWS` (Sun source-code browser, path to `.cb` file) shares this value.
     */
    N_BSLINE(0x48),

    /** GNU Modula-2 definition module dependency. Value is the modification time of the definition file. */
    N_DEFD(0x4A),

    /** Function start/body/end line numbers (Solaris2). */
    N_FLINE(0x4C),

    /** End of a relocatable function block + debugging info (macOS / Apple). */
    N_ENSYM(0x4E),

    /**
     * GNU C++ exception variable; name is the variable name.
     * Alias `N_MOD2` (Modula-2 info "for imc", Ultrix V4.0) shares this value.
     */
    N_EHDECL(0x50),

    /**
     * GNU C++ `catch` clause. Value is its address.
     * `desc` is non-zero if immediately followed by `CAUGHT` stab(s) naming the caught exception(s);
     * `desc == 0` means all exceptions are caught here.
     */
    N_CATCH(0x54),

    /** Structure or union element. Value is the offset within the structure. */
    N_SSYM(0x60),

    /** Last stab emitted for module (Solaris2). */
    N_ENDM(0x62),

    /**
     * Path and name of the main source file. Value is the starting text address of the compilation.
     * If multiple `N_SO` entries appear, the first ending in `/` is the compilation directory;
     * the first not ending in `/` is the source filename relative to that directory.
     * An `N_SO` with an empty name marks the *end* of the source file (value = end of text section).
     * The `desc` field optionally encodes the source language:
     * `0x1`=ASM, `0x2`=K&R C, `0x3`=ANSI C, `0x4`=C++, `0x5`=Fortran, `0x6`=Pascal,
     * `0x7`=Fortran90, `0x32`=ObjC, `0x33`=ObjC++.
     */
    N_SO(0x64),

    /**
     * Associates the `.o` file with the preceding `N_SO` stab (Apple/macOS).
     * String is the object file name; value is `st_mtime` (modification time of the `.o`).
     * Used when debug info is stored in the `.o` rather than the linked executable.
     */
    N_OSO(0x66),

    /** Name of an alias symbol (SunPro Fortran 77). */
    N_ALIAS(0x6C),

    /** Automatic (stack) variable; value is offset from frame pointer. Also used for type descriptions. */
    N_LSYM(0x80),

    /**
     * Beginning of an include file (Sun only).
     * In an object file only the name is significant; the Sun linker fills in additional fields.
     * The linker sets the value to a checksum of all stab strings in the header, used to
     * match against `N_EXCL` replacements for duplicate includes.
     */
    N_BINCL(0x82),

    /** Name of a sub-source (`#include`) file. Value is the starting text address of the compilation.
     * Only used to track line numbers
     * */
    N_SOL(0x84),

    /** Compiler parameters (Apple/Mach-O). String is the parameter name; other fields are zero. */
    N_PARAMS(0x86),

    /** Compiler version string (Apple/Mach-O). String is the version; other fields are zero. */
    N_VERSION(0x88),

    /** Compiler `-O` optimization level (Apple/Mach-O). String is the level; other fields are zero. */
    N_OLEVEL(0x8A),

    /** Parameter variable. Value is offset from the argument pointer. */
    N_PSYM(0xA0),

    /**
     * End of an include file. `N_BINCL` and `N_EINCL` bracket the file's output.
     * In an object file there is no significant data; the Sun linker fills in fields.
     * These pairs can be nested.
     */
    N_EINCL(0xA2),

    /**
     * Alternate entry point. Value is its address.
     * Only the name is significant in AIX/XCOFF (`C_ENTRY`); the address comes from the external symbol.
     */
    N_ENTRY(0xA4),

    /**
     * Beginning of a lexical block. `desc` is the nesting level; value is the start address of
     * the block's text (relative to the source file on most machines, absolute on Gould NP1,
     * relative to the enclosing function for stabs-in-sections).
     * Variables declared inside the block *precede* this symbol (with most compilers).
     */
    N_LBRAC(0xC0),

    /**
     * Placeholder for a deleted include file (Sun linker output only).
     * Replaces an `N_BINCL`…`N_EINCL` pair when the linker detects duplicate header stabs.
     * Its value equals the replaced `N_BINCL`'s checksum, enabling them to be matched by filename.
     */
    N_EXCL(0xC2),

    /** Modula-2 scope information (Sun linker). */
    N_SCOPE(0xC4),

    /** Patch Run Time Checker marker (Solaris2). */
    N_PATCH(0xD0),

    /**
     * End of a lexical block. `desc` matches the corresponding `N_LBRAC`'s desc.
     * Value is the end address of the block's text (same relativity rules as `N_LBRAC`).
     */
    N_RBRAC(0xE0),

    /** Begin named common block. Only the name is significant. */
    N_BCOMM(0xE2),

    /** End named common block. Only the name is significant (should match the `N_BCOMM`). */
    N_ECOMM(0xE4),

    /**
     * Member of a named common block; value is the offset within the common block.
     * Should appear within a `N_BCOMM`/`N_ECOMM` pair.
     */
    N_ECOML(0xE8),

    /** Pascal `with`-statement scope: `type,,0,0,offset` (Solaris2). */
    N_WITH(0xEA),

    /**
     * Gould systems non-base register symbol (text segment).
     * Note: GNU assigned these values without a Gould to verify against; actual Gould values may differ.
     */
    N_NBTEXT(0xF0),

    /**
     * Gould systems non-base register symbol (data segment).
     * Note: GNU assigned these values without a Gould to verify against; actual Gould values may differ.
     */
    N_NBDATA(0xF2),

    /**
     * Gould systems non-base register symbol (BSS segment).
     * Note: GNU assigned these values without a Gould to verify against; actual Gould values may differ.
     */
    N_NBBSS(0xF4),

    /**
     * Gould systems non-base register symbol (static segment).
     * Note: GNU assigned these values without a Gould to verify against; actual Gould values may differ.
     */
    N_NBSTS(0xF6),

    /**
     * Gould systems non-base register symbol (local common segment).
     * Note: GNU assigned these values without a Gould to verify against; actual Gould values may differ.
     */
    N_NBLCS(0xF8),

    /** Second symbol entry containing a length-value for the preceding entry. The value is the length. */
    N_LENG(0xFE),
    ;

    companion object {
        private val byCode: Map<Int, StabType> = entries.filter { it != UNKNOWN }.associateBy { it.code }

        fun fromCode(b: Int): StabType = byCode[b and 0xFF] ?: UNKNOWN
    }
}

/**
 * The mnemonics that may carry a `\`-continuation tail.
 * Mirrored from parse_image/stabs_stats.py:TYPES_WITH_CONTINUATION.
 */
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
 * One assembled stab record. `name` has already been extracted from `.stabstr`
 * with the per-CU offset applied and any `\`-continuation chains merged.
 *
 * `recordIndex` is the 0-based index of the FIRST physical record; subsequent
 * continuation records are absorbed and not surfaced.
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
 * Reads stab records from raw `.stab` and `.stabstr` byte arrays.
 * Handles per-CU offset tracking and `\`-continuation merging.
 *
 * Algorithm:
 * - Maintains `cuOff` (current CU start in stabstr) and `cuSize` (current CU stabstr size).
 * - When N_UNDF record is encountered: advance `cuOff += cuSize; cuSize = n_value`.
 * - For name-bearing records: compute `nameStart = cuOff + n_strx`; read NUL-terminated string.
 * - If type is in TYPES_WITH_CONTINUATION and string ends in `\`:
 *   - Peek at next physical record; if same type, drop `\` and concatenate.
 *   - Repeat until no more `\` or different type.
 *   - Continuation records are consumed (not yielded separately).
 * - Truncated tail (size % 12 != 0): callers should check [Result.truncatedTail] and log/handle as appropriate.
 */
class StabReader(
    private val stab: ByteArray,
    private val stabstr: ByteArray,
    private val littleEndian: Boolean = true,
) {
    data class Result(
        val records: List<StabRecord>,
        val recordCount: Int,
        /**
         * Number of unprocessed bytes at the end of the `.stab` section due to truncation
         * (size % 12 != 0). Callers should check this value and log/handle as appropriate.
         */
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

            // Handle N_UNDF: CU header record
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

            // Extract base name
            val cuEnd = if (cuSize > 0) cuOff + cuSize else stabstr.size
            var name = cstring(stabstr, cuOff + nStrx, cuEnd)

            // Handle continuation chains
            if (type in TYPES_WITH_CONTINUATION && name.endsWith("\\")) {
                name = name.dropLast(1) // Drop trailing backslash

                // Merge continuation records.
                // Spec says continuation records carry 0 in non-string fields; we trust this without asserting (gcc-conformant input only).
                while (buf.remaining() >= STAB_RECORD_SIZE) {
                    val peekPos = buf.position()
                    val contHeader = decodeRecord(buf)

                    // Check if continuation is for the same type
                    if (StabType.fromCode(contHeader.type) != type) {
                        // Not a continuation; back up
                        buf.position(peekPos)
                        break
                    }

                    // It's a continuation; consume it
                    val contName = cstring(stabstr, cuOff + contHeader.strx, cuEnd)
                    // Drop trailing backslash if present before concatenating
                    name += if (contName.endsWith("\\")) {
                        contName.dropLast(1)
                    } else {
                        contName
                    }
                    physicalIndex++

                    // Stop if no more backslashes
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
        // Find NUL terminator starting from 'start', bounded by endExclusive
        var idx = start
        while (idx < endExclusive && bytes[idx] != 0.toByte()) {
            idx++
        }
        val len = idx - start
        return if (len > 0) String(bytes, start, len, Charsets.UTF_8) else ""
    }

    companion object {
        /**
         * Read .stab and .stabstr from a Ghidra Program. Returns null if either block is missing.
         * Pure read — does not mutate the program.
         */
        fun fromProgram(program: Program): Result? {
            val mem = program.memory
            val stabBlock = mem.getBlock(".stab") ?: return null
            val stabstrBlock = mem.getBlock(".stabstr") ?: return null
            val stab = ByteArray(stabBlock.size.toInt())
            val stabstr = ByteArray(stabstrBlock.size.toInt())
            stabBlock.getBytes(stabBlock.start, stab)
            stabstrBlock.getBytes(stabstrBlock.start, stabstr)
            // x86 PE / x86 ELF: little-endian.
            val littleEndian = !program.memory.isBigEndian
            return StabReader(stab, stabstr, littleEndian).readAll()
        }
    }
}

/**
 * Raw stab record header fields, before type interpretation.
 */
private data class RawHeader(val strx: Int, val type: Int, val other: Int, val desc: Int, val value: Long)
