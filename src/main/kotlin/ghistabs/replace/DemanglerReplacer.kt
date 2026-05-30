package ghistabs.replace

import ghidra.program.model.data.Array
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeDependencyException
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.TypeDef
import ghistabs.builder.TypeRegistry
import ghistabs.importer.ImportContext
import java.util.ArrayDeque

/**
 * Adapter that uses Ghidra's DataTypeManager to execute demangler stub replacements.
 * Pure algorithm (DemanglerReplaceCore) is invoked to decide which stubs to replace;
 * this class handles the Ghidra-side DTM operations.
 */
class DemanglerReplacer(
    private val ctx: ImportContext,
    private val registry: TypeRegistry,
) {
    fun run() {
        val dtm = ctx.dtm

        // Build pure-record snapshot for the planner
        val stubs = mutableListOf<StubRecord>()
        val replacements = mutableMapOf<String, Pair<ReplacementRecord, DataType>>()
        val stubDtByPath = mutableMapOf<String, DataType>()

        // Precompute name-to-DataTypes index to avoid O(N²) registry.findByName lookups
        val nameIndex: Map<String, List<DataType>> =
            run {
                val map = mutableMapOf<String, MutableList<DataType>>()
                val it = dtm.allDataTypes
                while (it.hasNext()) {
                    val d = it.next()
                    map.getOrPut(d.name) { mutableListOf() }.add(d)
                }
                map
            }

        // Iterate all data types in DTM
        val allDts = dtm.allDataTypes
        while (allDts.hasNext()) {
            val dt = allDts.next()

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
            }

            // Collect potential replacements (from name index, structures with content)
            // Use nameIndex instead of registry.findByName to avoid O(N²) behavior
            val candidates = nameIndex[dt.name] ?: continue
            val candidate = if (candidates.size == 1) candidates[0] else null
            if (candidate == null || candidate !== dt) continue

            // Collect dependencies for cycle detection
            val deps = collectDependsOnPaths(dt)
            replacements[dt.name] =
                ReplacementRecord(dt.pathName, dt.name, deps) to dt
        }

        // Use pure core to decide which ops are safe
        val (ops, skips) =
            DemanglerReplaceCore.chooseReplaceOps(
                stubs,
                replacements.mapValues { it.value.first },
            )

        // Log all skips with per-kind counters
        for (skip in skips) {
            val counterKey =
                when (skip) {
                    is Skip.NoReplacement -> "demangler-skip-no-replacement"
                    is Skip.WouldBeCycle -> "demangler-skip-cycle"
                    is Skip.StubAlreadyMissing -> "demangler-skip-already-missing"
                }
            ctx.diagnostics.inc(counterKey)
            ctx.sink.log("demangler-skip", skip.reason)
        }

        // Execute replacements
        for (op in ops) {
            val stubDt = stubDtByPath[op.stubPath] ?: continue
            val replDt =
                replacements.values
                    .firstOrNull { it.first.pathName == op.replacementPath }
                    ?.second
                    ?: continue

            // Guard: stub must still exist in DTM
            if (!dtm.contains(stubDt)) continue

            try {
                // updateCategoryPath = false: keep replacement at its real category
                dtm.replaceDataType(stubDt, replDt, false)
                ctx.diagnostics.inc("replaced-demangler")
                ctx.sink.log("replaced-demangler", "${stubDt.pathName} -> ${replDt.pathName}")
            } catch (e: DataTypeDependencyException) {
                ctx.diagnostics.inc("replaced-demangler-failed")
                ctx.sink.log("replaced-demangler-failed", "${stubDt.pathName}: ${e.message}")
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
