package ghistabs.importer

import ghidra.program.database.data.DataTypeManagerDB
import ghidra.program.database.data.replaceDataTypesBatched
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghistabs.applyDemangling
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.degradation
import ghistabs.materialize.TypeRegistry
import ghistabs.materialize.itanium.RttiStructs
import ghistabs.parse.CATEGORY
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
 * [TypeRegistry.allCreatedDataTypes] only — no DTM-wide heuristics. The stub's path (sans `/Demangler`)
 * acts as the preferred-category hint when multiple candidates share a simple name.
 */
class DemanglerReplacer(private val ctx: ImportContext<*>, private val typeRegistry: TypeRegistry) :
    DiagnosticSink by ctx {
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

    /**
     * Ghidra's DemanglerAnalyzer is a BYTE_ANALYZER that only runs over loader-added symbols, missing the
     * raw mangled names we set from the stabs (function names in [SymbolApplier.applyAllFunctions], mangled
     * static labels in [SymbolApplier.ensureStabLabel]). Replicate it locally with signature /
     * calling-convention application off — stab signatures are richer and our __thiscall must win.
     * Runs first in [replace] so the `/Demangler/...` stubs it creates are visible to the scan below.
     */
    private fun demangleMangledLabels() {
        ctx.monitor.initialize(ctx.program.symbolTable.numSymbols.toLong(), "Stabs: demangling labels")
        var attempted = 0
        var demangled = 0
        for (sym in ctx.program.symbolTable.symbolIterator) {
            ctx.monitor.increment()
            val name = sym.name
            // Cygwin PE/COFF loader prepends `_`, so Itanium symbols appear as `__Z`.
            // GnuDemangler handles both (strips one leading `_`).
            if (!name.startsWith("_Z") && !name.startsWith("__Z")) continue
            attempted++
            if (ctx.program.applyDemangling(sym.address, name, monitor = ctx.monitor)) demangled++
        }
        debug("demangle-attempted", count = attempted.toLong())
        debug("demangle-applied", count = demangled.toLong())
    }

    fun replace() {
        demangleMangledLabels()
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
            // Priority: exact DTM name → exact demangler-link (byDemangledClass) → RTTI layout.
            val candidate = findByExactName(stub.simpleName, preferredCategory)?.also { debug("demangler-exact-match") }
                ?: typeRegistry.byDemangledClass[stub.pathName]?.also { debug("demangler-reverse-demangle-match") }
                ?: rtti.typeInfoLayout(stub.simpleName)?.let { dtm.resolve(it, null) }
                    ?.also { debug("demangler-rtti-match") }
                ?: continue
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
            debug(counterKey)
            // Only WouldBeCycle is a real degradation — we had a replacement and couldn't apply it.
            if (skip is Skip.WouldBeCycle) {
                degradation("demangler-skip-cycle", skip.name, skip.reason)
            }
        }

        val pairs = ops.mapNotNull { op ->
            val stubDt = stubDtByPath[op.stubPath] ?: return@mapNotNull null
            val replDt = replacements.values.firstOrNull { it.first.pathName == op.replacementPath }?.second
                ?: return@mapNotNull null
            if (dtm.contains(stubDt)) stubDt to replDt else null
        }
        // Batched: one whole-program reference sweep for all replacements (updateCategoryPath=false keeps
        // each at its real category), instead of Ghidra's per-`replaceDataType` sweep — O(stubs × program).
        try {
            (dtm as DataTypeManagerDB).replaceDataTypesBatched(pairs)
            pairs.forEach { (stub, repl) -> debug("replaced-demangler", "${stub.pathName} -> ${repl.pathName}") }
        } catch (e: Exception) {
            debug("replaced-demangler-failed")
            degradation("demangler-replace-failed", "batch of ${pairs.size}", e.message)
        }
    }

    private val rtti by lazy { RttiStructs(ctx.dtm) }

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

    /** Every datatype the registry materialized, by name (checked first, so exact names never go through normalization) */
    private val byExactName = typeRegistry.allCreatedDataTypes.groupBy { it.name }.mapValues { it.value.toSet() }

    /** Exact DTM-name match for a demangler stub — no spelling normalization. */
    fun findByExactName(simpleName: String, preferredCategory: CategoryPath? = null): DataType? =
        disambiguate(byExactName[simpleName].orEmpty(), simpleName, preferredCategory)

    /** Pick a single winner from [matches]; null when empty or genuinely ambiguous. */
    private fun disambiguate(
        matches: Collection<DataType>,
        simpleName: String,
        preferredCategory: CategoryPath?,
    ): DataType? {
        if (matches.isEmpty()) return null
        if (matches.size == 1) return matches.single()
        if (preferredCategory != null) {
            matches.firstOrNull { it.categoryPath == preferredCategory }?.let { return it }
        }
        // A typedef and its own resolved target both matching is not real ambiguity: typedef
        // shortening (OPT_SHORTEN_TYPEDEFS) renames the target struct onto the typedef's name
        // (`basic_string<…>` → `string`), so both a `string` typedef and a `string` struct — the
        // same type in two guises — end up named "string". Drop the target(s) a matching typedef
        // points at and keep the typedef, so the demangler stub is still replaceable (render-backlog §14).
        val typedefTargets = matches.filterIsInstance<TypeDef>().mapTo(mutableSetOf()) { it.baseDataType.pathName }
        val collapsed = matches.filterNot { it.pathName in typedefTargets }
        if (collapsed.size == 1) return collapsed.single()
        // A `/stabs/…` candidate is a ref-stub placeholder (makePlaceholder's home); the same
        // simple name in a CU/include category is the resolved type. When that leaves exactly
        // one non-placeholder, it's not real ambiguity — take it (locale facets hit this: the
        // demangler stub is `/Demangler/std/…`, matching neither the `/src/…` nor `/stabs/` home).
        collapsed.filterNot { CATEGORY.isAncestorOrSelf(it.categoryPath) }
            .singleOrNull()?.let { return it }
        log(
            "demangler-ambiguous",
            "Multiple matches for '$simpleName' (preferred=$preferredCategory): " +
                matches.joinToString { "${it.pathName}(${it::class.simpleName})" },
        )
        return null
    }
}
