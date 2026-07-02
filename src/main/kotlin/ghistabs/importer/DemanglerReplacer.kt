package ghistabs.importer

import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.TypeRegistry
import java.util.*

/** Pure-data input to the demangler-stub replacement planner. */
data class StubRecord(val pathName: String, val simpleName: String, val isEmptyStructure: Boolean)

data class ReplacementRecord(
    val pathName: String,
    val simpleName: String,
    val dependsOnPathNames: Set<String>,
    /** Typedef replacements can't form a self-cycle (see [DemanglerReplacer.decide]). */
    val isTypedef: Boolean = false,
)

data class ReplaceOp(val stubPath: String, val replacementPath: String)

sealed class Skip(open val reason: String) {
    data class NoReplacement(val name: String) : Skip("no-replacement-for-$name")
    data class WouldBeCycle(val name: String) : Skip("would-be-cycle-$name")
    data class StubAlreadyMissing(val path: String) : Skip("already-replaced-$path")
}

/**
 * Replaces empty `/Demangler/...` stubs with our registered types. Candidates come from
 * [TypeRegistry.findByName] only — no DTM-wide heuristics. The stub's path (sans `/Demangler`)
 * acts as the preferred-category hint when multiple candidates share a simple name.
 */
class DemanglerReplacer(private val ctx: ImportContext<*>, private val typeRegistry: TypeRegistry) :
    DiagnosticSink by ctx.sink {
    companion object {
        /** Pure planner: decide which stubs can be safely replaced. */
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

                // Cycle guard: skip Foo→Bar when Bar transitively contains Foo (post-replace
                // self-containment). Doesn't apply to typedef replacements: the normal C++
                // `std::string → basic_string<…>` pattern produces a benign typedef→struct→typedef
                // graph after replaceDataType, which Ghidra handles correctly.
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

        val stubs = mutableListOf<StubRecord>()
        val replacements = mutableMapOf<String, Pair<ReplacementRecord, DataType>>()
        val stubDtByPath = mutableMapOf<String, DataType>()

        for (dt in dtm.allDataTypes) {
            if (dt.categoryPath.path.startsWith("/Demangler") && dt is Structure) {
                stubs.add(
                    StubRecord(
                        pathName = dt.pathName,
                        simpleName = dt.name,
                        isEmptyStructure = dt.length == 0 || dt.numComponents == 0,
                    ),
                )
                stubDtByPath[dt.pathName] = dt
            }
        }

        // Only types WE registered qualify — swapping one Ghidra-bundled stub for another
        // is meaningless. Verified 2026-06-23: leaving non-registered stubs in place is a no-op.
        for (stub in stubs) {
            val preferredCategory = stub.pathName.removePrefix("/Demangler")
                .substringBeforeLast('/', missingDelimiterValue = "/")
                .ifEmpty { "/" }
                .let { CategoryPath(it) }
            val candidate = typeRegistry.findByName(stub.simpleName, preferredCategory) ?: continue
            val deps = collectDependsOnPaths(candidate)
            replacements[stub.simpleName] = ReplacementRecord(
                candidate.pathName,
                candidate.name,
                deps,
                candidate is TypeDef,
            ) to candidate
        }

        val (ops, skips) = decide(
            stubs,
            replacements.mapValues { it.value.first },
        )

        for (skip in skips) {
            val counterKey = when (skip) {
                is Skip.NoReplacement -> "demangler-skip-no-replacement"
                is Skip.WouldBeCycle -> "demangler-skip-cycle"
                is Skip.StubAlreadyMissing -> "demangler-skip-already-missing"
            }
            log(counterKey)
            // Only WouldBeCycle is a real degradation — we had a replacement and couldn't apply it.
            if (skip is Skip.WouldBeCycle) {
                ctx.diagnostics.recordDegradation("demangler-skip-cycle", skip.name, skip.reason)
            }
        }

        for (op in ops) {
            val stubDt = stubDtByPath[op.stubPath] ?: continue
            val replDt = replacements.values
                .firstOrNull { it.first.pathName == op.replacementPath }
                ?.second
                ?: continue

            if (!dtm.contains(stubDt)) continue

            try {
                // updateCategoryPath = false: keep replacement at its real category.
                dtm.replaceDataType(stubDt, replDt, false)
                log("replaced-demangler", "${stubDt.pathName} -> ${replDt.pathName}")
            } catch (e: Exception) {
                log("replaced-demangler-failed")
                ctx.diagnostics.recordDegradation(
                    "demangler-replace-failed",
                    stubDt.pathName,
                    e.message,
                )
            }
        }
    }

    /** Transitive dependency pathNames of [dt] (Structure components, Pointer/Array/TypeDef targets). Excludes self. */
    private fun collectDependsOnPaths(dt: DataType): Set<String> {
        val visited = mutableSetOf<String>()
        val queue = ArrayDeque<DataType>()
        queue.add(dt)

        while (queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            if (!visited.add(cur.pathName)) {
                continue
            }

            when (cur) {
                is Structure -> {
                    for (component in cur.components) {
                        val childDt = component.dataType
                        if (!visited.contains(childDt.pathName)) {
                            queue.add(childDt)
                        }
                    }
                }

                is Pointer -> {
                    val target = cur.dataType
                    if (target != null && !visited.contains(target.pathName)) {
                        queue.add(target)
                    }
                }

                is Array -> {
                    val elemDt = cur.dataType
                    if (!visited.contains(elemDt.pathName)) {
                        queue.add(elemDt)
                    }
                }

                is TypeDef -> {
                    val baseDt = cur.baseDataType
                    if (!visited.contains(baseDt.pathName)) {
                        queue.add(baseDt)
                    }
                }
            }
        }

        visited.remove(dt.pathName)
        return visited
    }
}
