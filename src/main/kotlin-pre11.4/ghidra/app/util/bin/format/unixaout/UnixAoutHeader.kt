package ghidra.app.util.bin.format.unixaout

import ghidra.app.util.bin.ByteProvider

/**
 * Ghidra gained the a.out loader, and this header with it, in 11.4. Below that no a.out program can
 * be loaded at all (what [ghistabs.LOADS_AOUT] probes for), so the only bytes a caller can reach
 * this with are some other format's — not a valid exec header, which is what this reports and the
 * answer the real parser would give.
 */
@Suppress("UNUSED_PARAMETER")
class UnixAoutHeader(provider: ByteProvider, isLittleEndian: Boolean) {
    enum class AoutType { OMAGIC, NMAGIC, ZMAGIC, QMAGIC, CMAGIC, UNKNOWN }

    val isValid = false
    val executableType = AoutType.UNKNOWN
    val languageSpec = ""
    val entryPoint = 0L
}
