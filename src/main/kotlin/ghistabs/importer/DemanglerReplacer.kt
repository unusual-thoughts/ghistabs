package ghistabs.importer

import ghidra.app.util.demangler.DemanglerUtil
import ghidra.program.database.data.DataTypeManagerDB
import ghidra.program.database.data.replaceDataTypesBatched
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolType
import ghidra.program.model.symbol.SymbolUtilities
import ghidra.util.task.TaskMonitor
import ghistabs.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.itanium.Itanium.isProbablyMangled
import ghistabs.materialize.itanium.Rtti
import ghistabs.parse.CATEGORY
import ghistabs.parse.canonTemplateName
import ghistabs.parse.splitQualified
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
class DemanglerReplacer(
    private val program: Program,
    private val registry: DataTypeRegistry,
    private val monitor: TaskMonitor,
    sink: DiagnosticSink,
) : DiagnosticSink by sink {
    companion object {
        /**
         * Pure planner: which stubs can be safely replaced, and why the rest can't. Ghidra's
         * DataTypes are plain objects — no Application runtime — so this stays a unit test.
         */
        fun decide(candidates: List<Pair<Structure, DataType?>>): Pair<List<Pair<Structure, DataType>>, List<Skip>> {
            val ops = mutableListOf<Pair<Structure, DataType>>()
            val skips = mutableListOf<Skip>()

            for ((stub, replacement) in candidates) {
                if (stub.length != 0 && stub.numComponents != 0) continue

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

        /**
         * Transitive dependency closure of [dt] by pathName, excluding self: [DataType.dependsOn]'s
         * relation — Pointer→pointee, Array→element, Typedef→target — plus by-value Composite
         * members, which `dependsOn` reports a flat `false` for. That gap is why
         * [DataTypeManagerDB]'s own `replacementDt.dependsOn(existingDt)` precondition never fires
         * for the struct replacements here.
         *
         * Must not descend into FunctionDefinition parameters, which is why the Ghidra reachability
         * walks are unusable: that makes every vtable-bearing class reach its own stub through its
         * virtual methods' `this`.
         */
        fun collectDependsOnPaths(dt: DataType): Set<String> {
            val visited = mutableSetOf<String>()
            val queue = ArrayDeque<DataType>()
            queue.add(dt)
            while (queue.isNotEmpty()) {
                val cur = queue.removeFirst()
                if (!visited.add(cur.pathName)) continue
                when (cur) {
                    is Composite -> cur.components.forEach { queue.add(it.dataType) }
                    is Pointer -> cur.dataType?.let { queue.add(it) }
                    is Array -> queue.add(cur.dataType)
                    is TypeDef -> queue.add(cur.baseDataType)
                    else -> {}
                }
            }
            return visited - dt.pathName
        }
    }

    private val dtm = program.dataTypeManager

    /**
     * Mangled name per address, captured during [demangleMangledLabels] because
     * [dropDisplacedMangledLabels] renames the symbol to its demangled leaf straight after — by the time
     * [retargetStubSites] runs, the template args are gone.
     */
    private val mangledByAddress = mutableMapOf<Address, String>()

    /**
     * The stabs' own mangled names. Ghidra's DemanglerAnalyzer already renamed the loader's symbols during
     * auto-analysis, so for a function it reached there is no mangled symbol left for
     * [demangleMangledLabels] to capture — but the harvest kept one.
     */
    private val harvestedMangled by lazy {
        registry.harvest.functions.filter { isProbablyMangled(it.name) }.associate { it.addr to it.name }
    }

    /**
     * Ghidra's DemanglerAnalyzer is a BYTE_ANALYZER that only runs over loader-added symbols, missing the
     * raw mangled names we set from the stabs (function names in [SymbolApplier.applyAllFunctions], mangled
     * static labels in [SymbolApplier.ensureStabLabel]). Replicate it locally with signature /
     * calling-convention application off — stab signatures are richer and our __thiscall must win.
     * Runs first in [replace] so the `/Demangler/...` stubs it creates are visible to the scan below.
     */
    private fun demangleMangledLabels() {
        monitor.initialize(program.symbolTable.numSymbols.toLong(), "Stabs: demangling labels")
        var attempted = 0
        var demangled = 0
        val failures = mutableMapOf<String, MutableList<String>>()
        for (sym in program.symbolTable.symbolIterator) {
            monitor.increment()
            val name = sym.name
            if (!isProbablyMangled(name)) continue
            mangledByAddress.putIfAbsent(sym.address, name)
            attempted++
            if (program.applyDemangling(sym.address, name, monitor = monitor)) {
                demangled++
            } else {
                // Two separable questions behind one "didn't apply": whether the *name* defeats the
                // demangler, or whether it demangles and only the apply step declines (already named,
                // symbol conflict…). Bucket by both so 12k failures read as a handful of causes.
                val parsed = if (Demangler.of(name) == null) "demangle-failed" else "demangle-not-applied"
                failures.getOrPut(parsed) { mutableListOf() }.add(name)
            }
        }
        debug("demangle-attempted", count = attempted.toLong())
        debug("demangle-applied", count = demangled.toLong())
        failures.forEach { (bucket, names) -> names.forEach { debug(bucket, it) } }
    }

    /**
     * Drop the mangled names a demangle pass displaces into a class namespace: `SetLabelPrimaryCmd`
     * renames the function symbol to the demangled form and re-creates the old name as a label
     * beside it, which nothing later clears since the address then reads as already-demangled.
     *
     * Global-namespace mangled symbols stay — that is the loader's own (or ours on a stripped
     * binary), and what [ghistabs.harvest.ProgramAddressResolver.resolve] looks methods up by. A displaced LABEL is
     * deleted; a FUNCTION is renamed instead, since deleting takes its only symbol.
     */
    private fun dropDisplacedMangledLabels() {
        val displaced = program.symbolTable.symbolIterator
            .filter { isProbablyMangled(it.name) && !it.parentNamespace.isGlobal }
            .toList()
        var dropped = 0
        var renamed = 0
        for (sym in displaced) {
            val leaf = Demangler.of(sym.name)?.name
            when {
                sym.symbolType == SymbolType.LABEL -> {
                    sym.delete()
                    dropped++
                }

                leaf != null -> {
                    program.symbolTable.getSymbols(sym.address)
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

    /** Choose the potential replacment for a stub structure */
    fun Structure.chooseReplacement(): DataType? {
        // The stub's own category with the /Demangler root lifted off (`/Demangler/std` → `/std`),
        // as the hint for which of several same-named candidates is meant.
        val preferredCategory = CategoryPath.ROOT.extend(
            categoryPath.pathElements.drop(DEMANGLER_CATEGORY.pathElements.size),
        )
        // A `.conflict` fork is a second stub Ghidra made for a name we already occupy; it
        // names the same type, so it looks up debased. Nothing else keys off the fork's name.
        val bareName = nameWithoutConflict
        // Priority: exact DTM name → exact demangler-link (byDemangledClass) → RTTI layout.
        // byDemangledClass stays below the name match but above anything inferred: it is grounded
        // in the mangled symbol's own `this`-pointee.
        return findByExactName(bareName, preferredCategory)?.also { debug("demangler-exact-match") }
            ?: registry.byDemangledClass[pathName]?.also { debug("demangler-reverse-demangle-match") }
            ?: soleInstantiation[bareName]?.also { debug("demangler-sole-instantiation-match", bareName) }
            ?: rtti.typeInfoLayout(bareName)?.let { dtm.resolve(it, null) }
                ?.also { debug("demangler-rtti-match") }
    }

    fun replace() {
        demangleMangledLabels()
        dropDisplacedMangledLabels()

        // Only types WE registered qualify — swapping one Ghidra-bundled stub for another is meaningless.
        val candidates = dtm.allDataTypes.asSequence()
            .filter { it.categoryPath.isAncestorOrSelf(DEMANGLER_CATEGORY) }
            .filterIsInstance<Structure>()
            .toList()
            .map { it to it.chooseReplacement() }

        val (ops, skips) = decide(candidates)

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

        // Both sides must be DTM-resident. A candidate can be a never-resolved XRef placeholder — still
        // detached, see DataTypeRegistry.seedPlaceholder — and replaceDataType rejects that with
        // "Unexpected ID for replacement datatype (-1)". Resolve it rather than drop the pair: the
        // candidate carries no fields either way, but replacing is what *removes* the /Demangler stub,
        // and skipping leaves it behind empty — the gap demanglerHasNoEmptyStubs guards.
        val pairs = ops.mapNotNull { (stub, repl) ->
            when {
                !dtm.contains(stub) -> null
                !dtm.contains(repl) -> stub to dtm.resolve(repl, DataTypeConflictHandler.DEFAULT_HANDLER)
                else -> stub to repl
            }
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
        dropEmptyConflictForks()
        retargetStubSites()
        censusUnboundStubs()
    }

    /**
     * Retype the signature sites that an empty stub reached, onto the instantiation the *site* means.
     *
     * `DemangledFunction.maybeCreateClassStructure` names its placeholder after the owning class
     * arity-free (`namespace.getName()`, template args living in a separate `DemangledType.template`),
     * and Ghidra's analyzer applies signatures — so `this` parameters and ctor returns end up typed by an
     * empty `DL_Base` that stands for 18 different instantiations. Replacing the stub itself can't fix
     * that: there is no single type it should become. Each *site* is unambiguous though, because the
     * owning method's own mangled name carries the args — `getNamespaceString()` renders the namespace
     * with its template, which normalizes onto our stab spelling.
     *
     * [DataTypeRegistry.byDemangledClass] is not usable here despite being the same kind of link: it is
     * keyed by the arity-free path and `putIfAbsent`s, so a bare key holds whichever instantiation was
     * harvested first — right for class identity, a coin flip for a retarget.
     */
    private fun retargetStubSites() {
        val unbound = dtm.allDataTypes.asSequence()
            .filter { it.categoryPath.isAncestorOrSelf(DEMANGLER_CATEGORY) }
            .filterIsInstance<Structure>()
            .filter { it.isZeroLength || it.numComponents == 0 }
            .toSet()
        if (unbound.isEmpty()) return

        for (f in program.functionManager.getFunctions(true)) {
            val hit = (f.parameters.map { it.dataType } + f.returnType)
                .mapNotNull { undecorate(it) }.filter { it in unbound }.distinct()
            if (hit.isEmpty()) continue
            val at = "${f.name}@${f.entryPoint} :: ${hit.joinToString { it.pathName }}"
            val spelling = when (val o = ownerSpelling(f)) {
                Owner.NoMangledName -> {
                    debug("demangler-retarget-no-mangled-name", at)
                    continue
                }

                Owner.DemangleFailed -> {
                    debug("demangler-retarget-demangle-failed", "$at <- ${mangledFor(f)}")
                    continue
                }

                Owner.NoNamespace -> {
                    debug("demangler-retarget-no-namespace", at)
                    continue
                }

                is Owner.Spelled -> o.name
            }
            val owner = findByExactName(spelling) ?: soleInstantiation[spelling]
            if (owner == null) {
                val n = instantiationsByBase[spelling.substringBefore('<')].orEmpty().size
                debug("demangler-retarget-no-type", "$spelling ($n instantiations) <- $at")
                continue
            }
            debug("demangler-retarget-bound", "$at -> ${owner.pathName}")
            for (p in f.parameters) {
                if (p.isAutoParameter) continue
                val redecorated = redecorate(p.dataType, owner) { it in unbound } ?: continue
                p.setDataType(redecorated, SourceType.IMPORTED)
                debug("demangler-retargeted-stub-site", at)
            }
            redecorate(f.returnType, owner) { it in unbound }?.let {
                f.setReturnType(it, SourceType.IMPORTED)
                debug("demangler-retargeted-stub-site", at)
            }
        }
    }

    /** Why [ownerSpelling] couldn't name the class owning a site. Each cause is counted separately —
     *  folding them loses which half of the lookup is failing, twice now. */
    private sealed interface Owner {
        data class Spelled(val name: String) : Owner
        data object NoMangledName : Owner
        data object DemangleFailed : Owner
        data object NoNamespace : Owner
    }

    /**
     * The type spelling of the class owning [f], from its own mangled name: `getNamespaceString()` renders
     * the namespace *with* its template args, and [Type.ghidraName]'s sanitizer carries that onto our stab
     * spelling. A free function demangles fine but has no namespace — distinct from having no mangled name
     * at all, and conflating the two hid which half was failing.
     */
    private fun mangledFor(f: Function): String? = mangledByAddress[f.entryPoint]
        ?: harvestedMangled[f.entryPoint]
        ?: program.symbolTable.getSymbols(f.entryPoint).firstOrNull { isProbablyMangled(it.name) }?.name

    private fun ownerSpelling(f: Function): Owner {
        val mangled = mangledFor(f) ?: return Owner.NoMangledName
        val demangled = Demangler.of(mangled) ?: return Owner.DemangleFailed
        val namespace = demangled.namespace ?: return Owner.NoNamespace
        val leaf = splitQualified(namespace.namespaceString).lastOrNull() ?: return Owner.NoNamespace
        return Owner.Spelled(ourSpelling(leaf))
    }

    /**
     * A demangled name in *our* spelling — the pipeline [Type.ghidraName] runs. Both the site lookup and
     * the instantiation census go through it, so "distinct instantiation" is measured in the same spelling
     * space we resolve in: three renderings of one class collapse to one, instead of declining a bind that
     * was only ever ambiguous as a string.
     */
    private fun ourSpelling(leaf: String): String = SymbolUtilities.replaceInvalidChars(
        DemanglerUtil.stripSuperfluousSignatureSpaces(canonTemplateName(leaf)),
        true,
    )

    /** [dt] with its pointer/array/typedef decoration rebuilt over [replacement], if its base matches [isTarget]. */
    private fun redecorate(dt: DataType?, replacement: DataType, isTarget: (DataType?) -> Boolean): DataType? = when {
        dt is Pointer -> redecorate(dt.dataType, replacement, isTarget)?.let { dtm.getPointer(it) }
        dt is TypeDef -> redecorate(dt.baseDataType, replacement, isTarget)
        isTarget(dt) -> replacement
        else -> null
    }

    /**
     * Who actually consumes an empty stub we couldn't bind. A bare template name (`DL_Base`, minted per
     * `__thiscall` method by `DemangledFunction.maybeCreateClassStructure`, which reads the class name
     * arity-free) names no instantiation in particular, but Ghidra's own analyzer applies signatures — so
     * it lands on `this` parameters and ctor/dtor returns.
     *
     * Those are Function signatures, not DataTypes: they create no parent edge, so `getParents()` sees only
     * the stub's own auto-created pointer and reports every stub as "referenced" while proving nothing.
     * Scan the FunctionManager instead, unwrapping pointer/array/typedef decoration.
     */
    private fun censusUnboundStubs() {
        val unbound = dtm.allDataTypes.asSequence()
            .filter { it.categoryPath.isAncestorOrSelf(DEMANGLER_CATEGORY) }
            .filterIsInstance<Structure>()
            .filter { it.isZeroLength || it.numComponents == 0 }
            .toSet()
        unbound.forEach { debug("demangler-unbound-stub", it.pathName) }

        val sites = mutableMapOf<DataType, MutableList<String>>()
        // Split by who put the type there. A decompiler-synthesized temp holding a stubbed `this` is
        // expected fallout of the stub existing; an IMPORTED parameter or local is one *we* applied from
        // stabs and got wrong, which is a different bug in a different pass.
        val byOrigin = mutableMapOf<String, Int>()
        fun note(dt: DataType?, where: String, origin: String) {
            val stub = undecorate(dt)?.takeIf { it in unbound } ?: return
            sites.getOrPut(stub) { mutableListOf() }.add(where)
            byOrigin.merge(origin, 1, Int::plus)
        }
        for (f in program.functionManager.getFunctions(true)) {
            note(f.returnType, "${f.name}:return", "return/${f.signatureSource}")
            f.parameters.forEach { note(it.dataType, "${f.name}:${it.name}", "param/${it.source}") }
            f.localVariables.forEach { note(it.dataType, "${f.name}:local ${it.name}", "local/${it.source}") }
        }
        byOrigin.entries.sortedByDescending { it.value }
            .forEach { (origin, n) -> debug("demangler-unbound-stub-site-origin", origin, count = n.toLong()) }
        sites.forEach { (stub, where) ->
            debug("demangler-unbound-stub-in-signature", "${stub.pathName} <- ${where.size} sites")
            where.forEach { debug("demangler-unbound-stub-signature-site", "${stub.pathName} <- $it") }
        }
    }

    /** Strip pointer/array/typedef decoration down to the underlying type. */
    private tailrec fun undecorate(dt: DataType?): DataType? = when (dt) {
        is Pointer -> undecorate(dt.dataType)
        is Array -> undecorate(dt.dataType)
        is TypeDef -> undecorate(dt.baseDataType)
        else -> dt
    }

    /**
     * Ghidra mints two incompatible types for one unknown name — `TypedefDataType(name, DataType.DEFAULT)`
     * where it appears by value, an empty placeholder Structure where by pointer/reference (both tails of
     * `DemangledDataType.getDataType`) — so whichever lands second forks to `.conflict`. We are what makes
     * both fire: [demangleMangledLabels] covers far more symbols than Ghidra's own DemanglerAnalyzer.
     *
     * A fork still empty here is a duplicate of a name its twin already holds, with nothing to bind to
     * (`__normal_iterator` is a bare template name — see DemanglerWhitelist). Drop it rather than leave a
     * junk type for the decompiler; the twin keeps the name.
     */
    private fun dropEmptyConflictForks() {
        val forks = dtm.allDataTypes.asSequence()
            .filter { it.categoryPath.isAncestorOrSelf(DEMANGLER_CATEGORY) }
            .filterIsInstance<Structure>()
            .filter { (it.isZeroLength || it.numComponents == 0) && it.isConflict() }
            .filter { dtm.conflictBase(it) != null }
            .toList()
        val dropped = forks.count { dtm.remove(it, monitor) }
        if (dropped > 0) debug("demangler-dropped-empty-conflict-fork", count = dropped.toLong())
    }

    private val rtti by lazy { Rtti(dtm) }

    /**
     * Every datatype the registry materialized, by name (checked first, so exact names never go
     * through normalization).
     */
    private val byExactName = registry.allCreatedDataTypes.groupBy { it.name }.mapValues { it.value.toSet() }

    /** Exact DTM-name match for a demangler stub — no spelling normalization. */
    fun findByExactName(simpleName: String, preferredCategory: CategoryPath? = null): DataType? =
        disambiguate(byExactName[simpleName].orEmpty(), simpleName, preferredCategory)

    /** Every instantiation we materialized, by the bare template name Ghidra's class-owner stub carries. */
    private val instantiationsByBase: Map<String, List<DataType>> by lazy {
        registry.allCreatedDataTypes
            .filter { it !is Pointer && it !is Array && '<' in it.name }
            .groupBy { it.name.substringBefore('<') }
            .mapValues { (_, v) -> v.distinctBy { it.pathName } }
    }

    /**
     * Every instantiation the *binary* names, by bare template name — read off the demangled symbols
     * rather than the stabs. Each mangled name carries its enclosing class with template args in
     * `DemangledType.template`, so the class spellings come from the demangler's own structure instead of
     * scanning strings. Only usable now that every symbol demangles; while 45% failed this would have
     * undercounted exactly the templates it was meant to guard.
     */
    private val instantiationsInBinary: Map<String, Set<String>> by lazy {
        buildMap<String, MutableSet<String>> {
            for (mangled in mangledByAddress.values) {
                var scope = Demangler.of(mangled)?.namespace
                while (scope != null) {
                    // Read the args off `namespaceString` — the same accessor [ownerSpelling] resolves
                    // sites through. `DemangledType.template` looks like the structured way to ask, but
                    // it is null on every namespace the GNU parser builds, so testing it counted nothing.
                    // Ghidra decorates a scope name with a `-in-<namespace>` disambiguator and pointer
                    // marks; left on, one class counts as three instantiations and vetoes its own bind.
                    // Requiring the leaf to close a template also drops non-class scopes.
                    val leaf = splitQualified(scope.namespaceString).lastOrNull()
                        ?.substringBefore("-in-")?.trimEnd('*', '&', ' ')
                    if (leaf != null && '<' in leaf && leaf.endsWith('>')) {
                        getOrPut(leaf.substringBefore('<')) { mutableSetOf() }.add(ourSpelling(leaf))
                    }
                    scope = scope.namespace
                }
            }
        }
    }

    /**
     * Bare template name → the instantiation it can only have meant: one we materialized, *and* one the
     * binary instantiates exactly once.
     *
     * The registry side alone is not enough. It counts stab types, and a template can be instantiated
     * many times while reaching the stabs once — COMDAT folding and dropped inline members are what
     * produce these stubs in the first place — so binding on it could pick the wrong instantiation for a
     * site. Requiring the binary's own symbols to name exactly one closes that: the arity-free stub then
     * has a single candidate in the program, not merely a single candidate in what we harvested.
     *
     * Declines when either side is ambiguous, and on a binary whose symbols name none — including
     * anything the stabs describe but no symbol mentions.
     */
    private val soleInstantiation: Map<String, DataType> by lazy {
        instantiationsByBase.filterValues { it.size == 1 }
            .filterKeys { base ->
                (instantiationsInBinary[base]?.size == 1).also {
                    if (!it) {
                        debug(
                            "demangler-sole-instantiation-declined",
                            "$base: ${instantiationsInBinary[base].orEmpty().joinToString(" | ")}",
                        )
                    }
                }
            }
            .mapValues { it.value.single() }
    }

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
