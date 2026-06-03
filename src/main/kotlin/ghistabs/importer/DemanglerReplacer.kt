package ghistabs.importer

import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghistabs.builder.TypeRegistry
import ghistabs.diag.DiagnosticSink
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
 */
class DemanglerReplacer(private val ctx: ImportContext<*>, private val registry: TypeRegistry) :
    DiagnosticSink by ctx.sink {
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

                if (stub.pathName in replacement.dependsOnPathNames) {
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
        // `/proj/bouniaf` paired with a stub `/Demangler/bouniaf`
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

            // Collect potential replacements (non-stub structures with content).
            val candidates = nameIndex[dt.name] ?: continue
            val candidate = if (candidates.size == 1) candidates[0] else null
            if (candidate == null || candidate !== dt) continue

            // Collect dependencies for cycle detection
            val deps = collectDependsOnPaths(dt)
            replacements[dt.name] = ReplacementRecord(dt.pathName, dt.name, deps) to dt
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
            log("demangler-skip", skip.reason)
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
            } catch (e: DataTypeDependencyException) {
                ctx.diagnostics.inc("replaced-demangler-failed")
                log("replaced-demangler-failed", "${stubDt.pathName}: ${e.message}")
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
