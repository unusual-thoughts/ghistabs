package ghistabs.importer

import ghistabs.harvest.SymbolRecord
import ghistabs.parse.StabType

/**
 * Pure scope-pairing logic for matching LBRAC/RBRAC records and filtering locals by recordIndex.
 */
internal object ScopePairs {
    /**
     * Pair LBRAC/RBRAC and filter locals by recordIndex.
     * Locals are included in a scope only if their recordIndex falls within
     * the bracket pair's recordIndex range (inclusive).
     *
     * @param scopeBrackets List of (StabType, offset, recordIndex) triples from stabs stream
     * @param locals List of local variable records
     * @return List of (openOffset, closeOffset, localsInScope) triples for each matched bracket pair
     */
    fun compute(
        scopeBrackets: List<Triple<StabType, Long, Int>>,
        locals: List<SymbolRecord>,
    ): List<Triple<Long, Long, List<SymbolRecord>>> {
        val pairs = mutableListOf<Triple<Long, Long, List<SymbolRecord>>>()
        val stack = mutableListOf<Triple<Int, Long, Int>>() // (bracketArrayIdx, offset, recordIdx)

        for ((arrIdx, bracket) in scopeBrackets.withIndex()) {
            val (type, off, recIdx) = bracket
            when (type) {
                StabType.N_LBRAC -> stack.add(Triple(arrIdx, off, recIdx))

                StabType.N_RBRAC if (stack.isNotEmpty()) -> {
                    val (_, openOff, openRec) = stack.removeAt(stack.size - 1)
                    val localsInScope = locals.filter { it.recordIndex in openRec..recIdx }
                    pairs.add(Triple(openOff, off, localsInScope))
                }

                else -> {}
            }
        }
        return pairs
    }
}
