package ghistabs.container

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * On-disk size in bytes of a single stab record (Sun a.out / PE-COFF / ELF).
 * Independent of host endianness.
 */
const val STAB_RECORD_SIZE: Int = 12

enum class StabType(val code: Int) {
    UNKNOWN(-1),
    N_UNDF(0x00), // CU header: n_value = stabstr size for this CU
    N_GSYM(0x20),
    N_FNAME(0x22),
    N_FUN(0x24),
    N_STSYM(0x26),
    N_LCSYM(0x28),
    N_MAIN(0x2A),
    N_PC(0x30),
    N_OPT(0x3C),
    N_RSYM(0x40),
    N_M2C(0x42),
    N_SLINE(0x44),
    N_DSLINE(0x46),
    N_BSLINE(0x48),
    N_DEFD(0x4A),
    N_FLINE(0x4C),
    N_EHDECL(0x50),
    N_CATCH(0x54),
    N_SSYM(0x60),
    N_ENDM(0x62),
    N_SO(0x64),
    N_OSO(0x66),
    N_LSYM(0x80),
    N_BINCL(0x82),
    N_SOL(0x84),
    N_PARAMS(0x86),
    N_VERSION(0x88),
    N_OLEVEL(0x8A),
    N_PSYM(0xA0),
    N_EINCL(0xA2),
    N_ENTRY(0xA4),
    N_LBRAC(0xC0),
    N_EXCL(0xC2),
    N_SCOPE(0xC4),
    N_RBRAC(0xE0),
    N_BCOMM(0xE2),
    N_ECOMM(0xE4),
    N_ECOML(0xE8),
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
    )

    fun readAll(): Result {
        val records = mutableListOf<StabRecord>()
        val buf =
            ByteBuffer.wrap(stab).apply {
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
                    name +=
                        if (contName.endsWith("\\")) {
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
        fun fromProgram(program: ghidra.program.model.listing.Program): Result? {
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
