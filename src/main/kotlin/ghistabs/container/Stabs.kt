package ghistabs.container

/**
 * On-disk size in bytes of a single stab record (Sun a.out / PE-COFF / ELF).
 * Independent of host endianness.
 */
const val STAB_RECORD_SIZE: Int = 12

enum class StabType(
    val code: Int,
) {
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
        private val byCode: Map<Int, StabType> =
            entries.filter { it != UNKNOWN }.associateBy { it.code }

        fun fromCode(b: Int): StabType = byCode[b and 0xFF] ?: UNKNOWN
    }
}

/**
 * The mnemonics that may carry a `\`-continuation tail.
 * Mirrored from parse_image/stabs_stats.py:TYPES_WITH_CONTINUATION.
 */
val TYPES_WITH_CONTINUATION: Set<StabType> =
    setOf(
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
