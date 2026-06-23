package ghistabs.importer

import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghistabs.diagnose.DiagnosticSink
import java.util.*

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
    val isTypedef: Boolean = false, // typedef replacements can't cycle on themselves
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
 * Adapter that uses Ghidra's DataTypeManager to execute demangler stub replacements.
 * FIXME: use  authoritative map of canonicalkey -> candidate instead of guessing (maybe use TypeRegistry.findByName)
 */
class DemanglerReplacer(private val ctx: ImportContext<*>) : DiagnosticSink by ctx.sink {
    companion object {
        /**
         * Pure algorithm: given stubs and replacements, decide which replacements are safe.
         */
        fun decide(
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

                // Cycle guard: avoid Foo→Bar where Bar transitively contains
                // Foo (would create a real self-containment after
                // replaceDataType). Doesn't apply to TypeDef replacements:
                // a typedef aliasing a struct that references the stub
                // (e.g. `std::string → basic_string<…>::operator=` taking
                // `std::string&`) is the normal C++ recursive type pattern
                // — replaceDataType rewrites those references to point at
                // the typedef, leaving a benign typedef→struct→typedef
                // graph that Ghidra handles correctly.
                if (!replacement.isTypedef && stub.pathName in replacement.dependsOnPathNames) {
                    skips.add(Skip.WouldBeCycle(stub.simpleName))
                    continue
                }

                ops.add(ReplaceOp(stub.pathName, replacement.pathName))
            }

            return ops to skips
        }
    }

    fun run() {
        val dtm = ctx.dtm

        // Build pure-record snapshot for the planner
        val stubs = mutableListOf<StubRecord>()
        val replacements = mutableMapOf<String, Pair<ReplacementRecord, DataType>>()
        val stubDtByPath = mutableMapOf<String, DataType>()

        // Precompute name-to-DataTypes index to find replacement candidates.
        // Exclude /Demangler/* entries — those are the stubs we want to *replace*,
        // not candidates to replace anything with. Without this filter, a real
        // `/proj/XapArgRegInst` paired with a stub `/Demangler/XapArgRegInst`
        // gives `candidates.size == 2`, both get skipped, and the stub remains.
        val nameIndex = dtm.allDataTypes.asSequence()
            .filterNot { it.categoryPath.path.startsWith("/Demangler") }
            .groupBy { it.name }

        for (dt in dtm.allDataTypes) {
            // Collect all stubs under /Demangler
            if (dt.categoryPath.path.startsWith("/Demangler") && dt is Structure) {
                val isEmptyStructure = dt.length == 0 || dt.numComponents == 0
                stubs.add(
                    StubRecord(
                        pathName = dt.pathName,
                        simpleName = dt.name,
                        isEmptyStructure = isEmptyStructure,
                    ),
                )
                stubDtByPath[dt.pathName] = dt
                continue
            }
        }

        // For each stub, find the best candidate among same-simple-name
        // DataTypes. With multiple candidates (e.g. `/string` built-in +
        // `/stabs/string` typedef + `/std/string` Structure), the old
        // size-must-be-1 rule rejected everything; instead prefer the
        // candidate whose path matches the stub's namespace path with
        // `/Demangler` stripped (so `/Demangler/std/string → /std/string`).
        // Fallback ranking: TypeDef > Structure > other.
        for (stub in stubs) {
            val candidates = nameIndex[stub.simpleName] ?: continue
            val preferredPath = stub.pathName.removePrefix("/Demangler")
            val candidate = candidates.firstOrNull { it.pathName == preferredPath }
                ?: candidates.firstOrNull { it is TypeDef }
                ?: candidates.firstOrNull { it is Structure }
                ?: candidates.singleOrNull()
                ?: continue
            val deps = collectDependsOnPaths(candidate)
            replacements[stub.simpleName] = ReplacementRecord(
                candidate.pathName,
                candidate.name,
                deps,
                candidate is TypeDef,
            ) to candidate
        }

        // Use pure core to decide which ops are safe
        val (ops, skips) = decide(
            stubs,
            replacements.mapValues { it.value.first },
        )

        // Log all skips with per-kind counters
        for (skip in skips) {
            val counterKey = when (skip) {
                is Skip.NoReplacement -> "demangler-skip-no-replacement"
                is Skip.WouldBeCycle -> "demangler-skip-cycle"
                is Skip.StubAlreadyMissing -> "demangler-skip-already-missing"
            }
            ctx.diagnostics.inc(counterKey)
            // Only WouldBeCycle is a real degradation: we had a replacement and
            // couldn't apply it. NoReplacement means there was no stab type that
            // matched the stub at all (often a third-party stub); not lossy.
            if (skip is Skip.WouldBeCycle) {
                ctx.diagnostics.recordDegradation("demangler-skip-cycle", skip.name, skip.reason)
            }
        }

        // Execute replacements
        for (op in ops) {
            val stubDt = stubDtByPath[op.stubPath] ?: continue
            val replDt = replacements.values
                .firstOrNull { it.first.pathName == op.replacementPath }
                ?.second
                ?: continue

            // Guard: stub must still exist in DTM
            if (!dtm.contains(stubDt)) continue

            try {
                // updateCategoryPath = false: keep replacement at its real category
                dtm.replaceDataType(stubDt, replDt, false)
                ctx.diagnostics.inc("replaced-demangler")
                log("replaced-demangler", "${stubDt.pathName} -> ${replDt.pathName}")
            } catch (e: Exception) {
                ctx.diagnostics.inc("replaced-demangler-failed")
                ctx.diagnostics.recordDegradation(
                    "demangler-replace-failed",
                    stubDt.pathName,
                    e.message,
                )
            }
        }
    }

    /**
     * Collect all data type paths that a given DataType depends on, transitively.
     * Walks Structure components, Pointer targets, Array element types, and TypeDef bases.
     * Uses BFS to detect cycles via visited set. Excludes self.
     *
     * @param dt the DataType to analyze
     * @return the set of all transitive dependency paths (excludes dt's own pathName)
     */
    private fun collectDependsOnPaths(dt: DataType): Set<String> {
        val visited = mutableSetOf<String>()
        val queue = ArrayDeque<DataType>()
        queue.add(dt)

        while (queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            // Mark visited by pathName to detect cycles
            if (!visited.add(cur.pathName)) {
                // Already visited, skip
                continue
            }

            // Walk dependencies of current type
            when (cur) {
                is Structure -> {
                    // Add all component data types
                    for (component in cur.components) {
                        val childDt = component.dataType
                        if (!visited.contains(childDt.pathName)) {
                            queue.add(childDt)
                        }
                    }
                }

                is Pointer -> {
                    // Add pointed-to type if it exists
                    val target = cur.dataType
                    if (target != null && !visited.contains(target.pathName)) {
                        queue.add(target)
                    }
                }

                is Array -> {
                    // Add element type
                    val elemDt = cur.dataType
                    if (!visited.contains(elemDt.pathName)) {
                        queue.add(elemDt)
                    }
                }

                is TypeDef -> {
                    // Add base type
                    val baseDt = cur.baseDataType
                    if (!visited.contains(baseDt.pathName)) {
                        queue.add(baseDt)
                    }
                }
                // Primitive types and others have no dependencies
            }
        }

        // Exclude self from results
        visited.remove(dt.pathName)
        return visited
    }
}
