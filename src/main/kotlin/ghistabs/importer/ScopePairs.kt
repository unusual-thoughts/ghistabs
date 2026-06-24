package ghistabs.importer

import ghistabs.harvest.SymbolRecord
import ghistabs.parse.StabType

/** Pure pairing of LBRAC/RBRAC brackets; each scope keeps locals whose recordIndex falls inside it. */
internal object ScopePairs {
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
