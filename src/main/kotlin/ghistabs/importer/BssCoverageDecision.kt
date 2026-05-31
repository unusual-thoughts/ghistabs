package ghistabs.importer

/**
 * Pure data class for a harvested symbol's address information.
 *
 * @property symbolName The name of the symbol.
 * @property resolvedAddr The resolved address, or null if unresolved.
 */
data class HarvestedAddr(
    val symbolName: String,
    val resolvedAddr: Long?,
)

/**
 * Range of addresses (inclusive on both ends).
 *
 * @property start The start address (inclusive).
 * @property endInclusive The end address (inclusive).
 */
data class AddrRange(
    val start: Long,
    val endInclusive: Long,
)

/**
 * Result of coverage analysis for an address range.
 */
sealed class CoverageResult {
    /**
     * The range has no coverage from any harvested symbols.
     */
    data class NoCoverage(
        val range: AddrRange,
    ) : CoverageResult()

    /**
     * The range is covered by one or more harvested symbols.
     */
    data class Covered(
        val range: AddrRange,
        val coverers: List<HarvestedAddr>,
    ) : CoverageResult()
}

/**
 * Pure decision logic for .bss coverage analysis.
 * Classifies whether an address range is covered by harvested symbols.
 */
object BssCoverageDecision {
    /**
     * Classify the coverage of an address range by harvested symbols.
     *
     * @param range The address range to analyze.
     * @param harvest The list of harvested symbols with their addresses.
     * @return NoCoverage if no symbols resolve within the range, Covered otherwise.
     */
    fun classify(
        range: AddrRange,
        harvest: List<HarvestedAddr>,
    ): CoverageResult {
        val matching =
            harvest.filter { it.resolvedAddr != null && it.resolvedAddr in range.start..range.endInclusive }
        return if (matching.isEmpty()) {
            CoverageResult.NoCoverage(range)
        } else {
            CoverageResult.Covered(range, matching)
        }
    }
}
