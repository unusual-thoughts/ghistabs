package ghistabs.importer

data class HarvestedAddr(val symbolName: String, val resolvedAddr: Long?)

/** Inclusive address range. */
data class AddrRange(val start: Long, val endInclusive: Long) {
    operator fun contains(addr: Long) = addr in start..endInclusive
}

sealed class CoverageResult {
    data class NoCoverage(val range: AddrRange) : CoverageResult()
    data class Covered(val range: AddrRange, val coverers: List<HarvestedAddr>) : CoverageResult()
}

/** Pure classification: is [AddrRange] covered by any harvested symbols. */
object BssCoverageDecision {
    fun classify(range: AddrRange, harvest: List<HarvestedAddr>): CoverageResult {
        val matching = harvest.filter { it.resolvedAddr != null && it.resolvedAddr in range }
        return if (matching.isEmpty()) {
            CoverageResult.NoCoverage(range)
        } else {
            CoverageResult.Covered(range, matching)
        }
    }
}
