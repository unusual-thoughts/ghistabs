package ghistabs.replace

/**
 * Pure data records for demangler replacement decision logic.
 * No Ghidra imports — this is pure data.
 */
data class StubRecord(
    val pathName: String, // e.g. "/Demangler/Foo"
    val simpleName: String, // e.g. "Foo"
    val isEmptyStructure: Boolean,
)

data class ReplacementRecord(
    val pathName: String, // e.g. "/proj/Foo"
    val simpleName: String,
    val dependsOnPathNames: Set<String>, // simulated dependsOn lookup
)

data class ReplaceOp(val stubPath: String, val replacementPath: String)

/**
 * Reason why a stub was skipped (not replaced).
 */
sealed class Skip(open val reason: String) {
    data class NoReplacement(val name: String) : Skip("no-replacement-for-$name")

    data class WouldBeCycle(val name: String) : Skip("would-be-cycle-$name")

    data class StubAlreadyMissing(val path: String) : Skip("already-replaced-$path")
}

/**
 * Pure algorithm: given stubs and replacements, decide which replacements are safe.
 */
object DemanglerReplaceCore {
    fun chooseReplaceOps(
        stubs: List<StubRecord>,
        replacements: Map<String, ReplacementRecord>,
    ): Pair<List<ReplaceOp>, List<Skip>> {
        val ops = mutableListOf<ReplaceOp>()
        val skips = mutableListOf<Skip>()

        for (stub in stubs) {
            if (!stub.isEmptyStructure) continue

            val replacement = replacements[stub.simpleName]
            if (replacement == null) {
                skips.add(Skip.NoReplacement(stub.simpleName))
                continue
            }

            if (stub.pathName in replacement.dependsOnPathNames) {
                skips.add(Skip.WouldBeCycle(stub.simpleName))
                continue
            }

            ops.add(ReplaceOp(stub.pathName, replacement.pathName))
        }

        return ops to skips
    }
}
