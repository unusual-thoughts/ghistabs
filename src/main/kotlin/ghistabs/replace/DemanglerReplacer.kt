package ghistabs.replace

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeDependencyException
import ghidra.program.model.data.Structure
import ghistabs.builder.TypeRegistry
import ghistabs.importer.ImportContext

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

            // Collect potential replacements (from registry, structures with content)
            val candidate = registry.findByName(dt.name) ?: continue
            if (candidate !== dt) continue

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

        // Log all skips
        for (skip in skips) {
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
     * Collect all data type paths that a given DataType depends on.
     * For Structures, walks components and collects their dtPathName;
     * for others, returns empty set.
     */
    private fun collectDependsOnPaths(dt: DataType): Set<String> {
        if (dt !is Structure) return emptySet()

        val deps = mutableSetOf<String>()
        for (component in dt.components) {
            deps.add(component.dataType.pathName)
        }
        return deps
    }
}
