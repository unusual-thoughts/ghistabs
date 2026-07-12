package ghistabs.importer

import ghidra.program.model.address.Address
import ghistabs.harvest.Harvest
import ghistabs.parse.SymbolDecl

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

/**
 * Sweep `.bss` in 4-byte chunks and log which ranges the harvested globals do — and don't — cover,
 * coalescing contiguous no-coverage into one entry per range (a per-chunk log floods typical .bss).
 */
fun ImportContext<*>.analyzeBssCoverage(harvest: Harvest) {
    val bssBlock = program.memory.getBlock(".bss") ?: return

    val harvestedAddrs = harvest.symbolsByCu.values.flatten().mapNotNull {
        val name = (it.body as? SymbolDecl.Global)?.name ?: return@mapNotNull null
        HarvestedAddr(name, resolver.resolve(name)?.offset)
    }

    var addr = bssBlock.start
    var gapStart: Address? = null
    var gapEnd: Address? = null

    fun flushGap() {
        val start = gapStart ?: return
        val end = gapEnd ?: return
        debug(
            "stabs-no-coverage",
            "@ $start..$end (${end.offset - start.offset + 1} bytes): no stabs records cover this range",
            address = start,
        )
        gapStart = null
        gapEnd = null
    }

    while (addr <= bssBlock.end) {
        monitor.checkCancelled()
        val rangeEnd = addr.add(3)

        val occupied = program.symbolTable.getPrimarySymbol(addr) != null ||
            program.listing.getDefinedDataAt(addr) != null
        if (occupied) {
            flushGap()
        } else {
            when (val result = BssCoverageDecision.classify(AddrRange(addr.offset, rangeEnd.offset), harvestedAddrs)) {
                is CoverageResult.NoCoverage -> {
                    if (gapStart == null) gapStart = addr
                    gapEnd = rangeEnd
                }

                is CoverageResult.Covered -> {
                    flushGap()
                    result.coverers.forEach {
                        debug("stabs-coverage", "@ $addr..$rangeEnd: covered by ${it.symbolName}")
                    }
                }
            }
        }

        addr = addr.add(4)
    }
    flushGap()
}
