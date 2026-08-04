package ghistabs.importer

import ghidra.program.database.data.DataTypeManagerDB
import ghidra.program.database.data.replaceDataTypesBatched
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolType
import ghistabs.applyDemangling
import ghistabs.demangle
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.degradation
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.itanium.RttiStructs
import ghistabs.parse.CATEGORY
import ghistabs.parse.isMangled
import java.util.*

sealed class Skip(open val reason: String) {
    data class NoReplacement(val name: String) : Skip("no-replacement-for-$name")
    data class WouldBeCycle(val name: String) : Skip("would-be-cycle-$name")
}

/**
 * Replaces empty `/Demangler/...` stubs with our registered types. Candidates come from
 * [DataTypeRegistry.allCreatedDataTypes] only — no DTM-wide heuristics. The stub's path (sans `/Demangler`)
 * acts as the preferred-category hint when multiple candidates share a simple name.
 */
class DemanglerReplacer(private val ctx: ImportContext<*>, private val registry: DataTypeRegistry) :
    DiagnosticSink by ctx {
    companion object {
        val DEMANGLER_CATEGORY: CategoryPath = CategoryPath.ROOT.extend("Demangler")

        /**
         * Pure planner: which stubs can be safely replaced, and why the rest can't. Ghidra's
         * DataTypes are plain objects — no Application runtime — so this stays a unit test.
         */
        fun decide(
            stubs: List<Structure>,
            replacements: Map<String, DataType>,
        ): Pair<List<Pair<Structure, DataType>>, List<Skip>> {
            val ops = mutableListOf<Pair<Structure, DataType>>()
            val skips = mutableListOf<Skip>()

            for (stub in stubs) {
                if (stub.length != 0 && stub.numComponents != 0) continue

                val replacement = replacements[stub.name]
                if (replacement == null) {
                    skips.add(Skip.NoReplacement(stub.name))
                    continue
                }

                // Cycle guard: skip Foo→Bar when Bar transitively contains Foo (post-replace
                // self-containment). Doesn't apply to typedef replacements: the normal C++
                // `std::string → basic_string<…>` pattern produces a benign typedef→struct→typedef
                // graph after replaceDataType, which Ghidra handles correctly.
                if (replacement !is TypeDef && stub.pathName in collectDependsOnPaths(replacement)) {
                    skips.add(Skip.WouldBeCycle(stub.name))
                    continue
                }

                ops.add(stub to replacement)
            }

            return ops to skips
        }

        /** Transitive dependency pathNames of [dt] (Structure components, Pointer/Array/TypeDef targets). Excludes self. */
        fun collectDependsOnPaths(dt: DataType): Set<String> {
            val visited = mutableSetOf<String>()
            val queue = ArrayDeque<DataType>()
            queue.add(dt)

            while (queue.isNotEmpty()) {
                val cur = queue.removeFirst()
                if (!visited.add(cur.pathName)) continue
                when (cur) {
                    is Structure -> cur.components.forEach { queue.add(it.dataType) }
                    is Pointer -> cur.dataType?.let { queue.add(it) }
                    is Array -> queue.add(cur.dataType)
                    is TypeDef -> queue.add(cur.baseDataType)
                    else -> {}
                }
            }

            visited.remove(dt.pathName)
            return visited
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
            if (!isMangled(name)) continue
            attempted++
            if (ctx.program.applyDemangling(sym.address, name, monitor = ctx.monitor)) demangled++
        }
        debug("demangle-attempted", count = attempted.toLong())
        debug("demangle-applied", count = demangled.toLong())
    }

    /**
     * Drop the mangled names a demangle pass displaces into a class namespace: `SetLabelPrimaryCmd`
     * renames the function symbol to the demangled form and re-creates the old name as a label
     * beside it, which nothing later clears since the address then reads as already-demangled.
     *
     * Global-namespace mangled symbols stay — that is the loader's own (or ours on a stripped
     * binary), and what [ProgramAddressResolver.resolve] looks methods up by. A displaced LABEL is
     * deleted; a FUNCTION is renamed instead, since deleting takes its only symbol.
     */
    private fun dropDisplacedMangledLabels() {
        val displaced = ctx.program.symbolTable.symbolIterator
            .filter { isMangled(it.name) && !it.parentNamespace.isGlobal }
            .toList()
        var dropped = 0
        var renamed = 0
        for (sym in displaced) {
            val leaf = demangle(sym.name)?.name
            when {
                sym.symbolType == SymbolType.LABEL -> {
                    sym.delete()
                    dropped++
                }

                leaf != null -> {
                    ctx.program.symbolTable.getSymbols(sym.address)
                        .filter { it != sym && it.name == leaf }
                        .forEach { it.delete() }
                    sym.setName(leaf, SourceType.IMPORTED)
                    renamed++
                }
            }
        }
        debug("demangle-displaced-label-dropped", count = dropped.toLong())
        debug("demangle-displaced-function-renamed", count = renamed.toLong())
    }

    fun replace() {
        demangleMangledLabels()
        dropDisplacedMangledLabels()
        val dtm = ctx.dtm

        val stubs = dtm.allDataTypes.asSequence()
            .filter { it.categoryPath.isAncestorOrSelf(DEMANGLER_CATEGORY) }
            .filterIsInstance<Structure>()
            .toList()
        val replacements = mutableMapOf<String, DataType>()

        // Only types WE registered qualify — swapping one Ghidra-bundled stub for another
        // is meaningless. Verified 2026-06-23: leaving non-registered stubs in place is a no-op.
        for (stub in stubs) {
            // The stub's own category with the /Demangler root lifted off (`/Demangler/std` → `/std`),
            // as the hint for which of several same-named candidates is meant.
            val preferredCategory = CategoryPath.ROOT.extend(
                stub.categoryPath.pathElements.drop(DEMANGLER_CATEGORY.pathElements.size),
            )
            // Priority: exact DTM name → exact demangler-link (byDemangledClass) → RTTI layout.
            val candidate = findByExactName(stub.name, preferredCategory)?.also { debug("demangler-exact-match") }
                ?: registry.byDemangledClass[stub.pathName]?.also { debug("demangler-reverse-demangle-match") }
                ?: rtti.typeInfoLayout(stub.name)?.let { dtm.resolve(it, null) }
                    ?.also { debug("demangler-rtti-match") }
                ?: continue
            replacements[stub.name] = candidate
        }

        val (ops, skips) = decide(stubs, replacements)

        for (skip in skips) {
            val counterKey = when (skip) {
                is Skip.NoReplacement -> "demangler-skip-no-replacement"
                is Skip.WouldBeCycle -> "demangler-skip-cycle"
            }
            debug(counterKey)
            // Only WouldBeCycle is a real degradation — we had a replacement and couldn't apply it.
            if (skip is Skip.WouldBeCycle) {
                degradation("demangler-skip-cycle", skip.name, skip.reason)
            }
        }

        val pairs = ops.filter { (stub, _) -> dtm.contains(stub) }
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

    /** Every datatype the registry materialized, by name (checked first, so exact names never go through normalization) */
    private val byExactName = registry.allCreatedDataTypes.groupBy { it.name }.mapValues { it.value.toSet() }

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
        collapsed.filterNot { it.categoryPath.isAncestorOrSelf(CATEGORY) }
            .singleOrNull()?.let { return it }
        log(
            "demangler-ambiguous",
            "Multiple matches for '$simpleName' (preferred=$preferredCategory): " +
                matches.joinToString { "${it.pathName}(${it::class.simpleName})" },
        )
        return null
    }
}
