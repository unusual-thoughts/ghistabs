package ghistabs.importer

import ghistabs.container.StabType

/**
 * Test helper to expose StabsImporter's private functions for unit testing.
 * This enables pure unit tests of the computePairs algorithm without Ghidra dependencies.
 */
object StabsImporterTestHelper {
    /**
     * Mirrors the private computePairs function for testing.
     * Pairs LBRAC/RBRAC and filters locals by recordIndex.
     */
    fun computePairs(
        scopeBrackets: List<Triple<StabType, Long, Int>>,
        locals: List<LocalRecord>,
    ): List<Triple<Long, Long, List<LocalRecord>>> {
        // Mirrors the private implementation in StabsImporter
        val pairs = mutableListOf<Triple<Long, Long, List<LocalRecord>>>()
        val stack = mutableListOf<Triple<Int, Long, Int>>() // (bracketArrayIdx, offset, recordIdx)

        for ((arrIdx, bracket) in scopeBrackets.withIndex()) {
            val (type, off, recIdx) = bracket
            when (type) {
                StabType.N_LBRAC -> {
                    stack.add(Triple(arrIdx, off, recIdx))
                }

                StabType.N_RBRAC -> {
                    if (stack.isNotEmpty()) {
                        val (_, openOff, openRec) = stack.removeAt(stack.size - 1)
                        val closeOff = off
                        val closeRec = recIdx
                        val localsInScope = locals.filter { it.recordIndex in openRec..closeRec }
                        pairs.add(Triple(openOff, closeOff, localsInScope))
                    }
                }

                else -> {}
            }
        }
        return pairs
    }
}
