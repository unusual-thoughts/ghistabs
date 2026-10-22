package ghistabs.importer

import ghistabs.entrypoints.GccVftableAnalyzer
import ghistabs.entrypoints.RttiLayoutAnalyzer
import ghistabs.entrypoints.SjljContextAnalyzer
import ghistabs.entrypoints.VirtualBaseAnalyzer
import ghistabs.harvest.Harvest
import ghistabs.harvest.Harvester
import ghistabs.importer.ImportOptions.Companion.markStabsTypedefsShortened
import ghistabs.index.TypeGraph
import ghistabs.materialize.*
import ghistabs.materialize.cpp.VtableVirtualBases
import ghistabs.materialize.cpp.layClasses
import ghistabs.materialize.cpp.uniqueStructTagged
import ghistabs.parse.StabReader
import ghistabs.parse.StaticScope
import ghistabs.parse.leafName
import ghistabs.runTransaction
import java.nio.file.Path

/**
 * Pass A's input, the raw records: null when the program carries none. Either way, says why a read
 * that comes back empty-handed did: a linker index in place of the stabs, a string table the
 * records have lost, names pointing past it.
 */
fun ImportContext<*>.readStabs(): StabReader.Result? {
    StabReader.verdictOf(program)?.let { (category, message) -> warn(category, message) }
    return StabReader.fromProgram(program)?.readAll(monitor)?.also { stabs ->
        stabs.unresolvedNames.takeIf { it > 0 }?.let {
            warn(
                "stabstr-out-of-range",
                "$it records name an offset past the string table; read as nameless",
                count = it.toLong(),
            )
        }
    } ?: run {
        warn("no-stabs", "No .stab/.stabstr block found.")
        null
    }
}

/**
 * Orchestrates the stabs import pipeline: harvest records → materialize types → apply symbols.
 * The heavy lifting lives in [Harvester] (harvest), [DataTypeRegistry] (materialize) and
 * [SymbolApplier] (apply); this class only sequences them and tallies the result.
 */
internal fun ImportContext<*>.runOnRecords(stabs: StabReader.Result): ImportResult {
    // Pass A — parse + harvest
    val harvest = harvester().harvest(stabs.records)
    // The three indexes over it, constructed together and handed out by half: resolution to the
    // passes that resolve, folding to the ones that render, the vote to the one that places.
    val hints = hints(harvest)
    recordHarvestCounters(harvest, hints.types, stabs)

    // Pass B — materialize types
    val registry = DataTypeRegistry(dtm, this, diagnostics, hints, monitor)
    val materialized = program.runTransaction("Stabs: materialize types") {
        registry.materializeAll().also {
            if (options.shortenTypedefs) registry.shortenTypedefs(monitor)
            registry.layClasses(options.vfptrModel.takeIf { options.buildClasses })
            // The render spells types to match the decompiler, and it may run much later from the GUI
            // against analyzer options that have since been toggled — so record what actually happened.
            program.markStabsTypedefsShortened(options.shortenTypedefs)
        }
    }

    // Pass C — apply symbols, then build classes/vtables, demangle, and replace demangler stubs
    val applied = program.runTransaction("Stabs: apply symbols") {
        SymbolApplier(this, registry).run {
            ImportResult.ApplyResults(
                functions = applyAllFunctions(),
                globals = applyAllGlobals(),
                constants = applyAllConstants(),
                staticMembers = applyAllStaticMembers(),
                classes = when {
                    options.buildClasses -> classApplier(registry).applyAll()
                    else -> 0
                },
            )
        }.also { layAfterSymbols(registry) }
    }

    // Pass D — publish the line map, then point it at local sources if any root was given
    val sourceMapEntries = program.runTransaction("Stabs: publish source map") {
        SourceMapApplier(this, hints.sources).apply()
    }
    program.applySourceRoots(options.sourceRoots.map(Path::of), this)

    analyzeDataCoverage()
    registry.reportSurvivingPlaceholders()
    registry.reportConflictDelta()
    diagnostics.writeSummary(terminal)
    val parseErrors = diagnostics["parse-error"].toInt()

    return ImportResult(
        parsed = ImportResult.ParseResults(stabs, parseErrors),
        types = ImportResult.TypeResults(harvested = harvest.types.size, materialized = materialized),
        applied = applied,
        sourceMapEntries = sourceMapEntries,
        artifacts = ImportArtifacts(registry, stabs.records),
    )
}

/** The ABI passes that need the stabs' symbols applied first, in the order each depends on. */
private fun ImportContext<*>.layAfterSymbols(registry: DataTypeRegistry) {
    // Typeinfos first, so the coverage report counts them in every analysis order: some
    // `_ZTI` labels only exist once this import has applied its globals.
    if (RttiLayoutAnalyzer.isEnabled(program)) {
        RttiLayoutAnalyzer.layTypeinfos(program, registry, this)
    }
    // The classes the stabs describe are laid; the analyzer's sweep takes the rest now, on
    // this import's registry and diagnostics, ahead of the demangler stub replacement.
    if (GccVftableAnalyzer.isEnabled(program)) {
        GccVftableAnalyzer.sweep(program, registry, monitor, this)
    }
    demanglerReplacer(registry).replace()
    // After the demangle passes above, which re-file methods under their mangled scope, and before
    // the virtual bases, which find a class's struct by the namespace its labels sit in.
    if (options.shortenTypedefs && options.buildClasses) {
        program.rehomeOntoShortenedClasses(TemplateNameShortener(registry.typedefAliases()), this)
    }
    // Once labels are demangled, so each typeinfo and vtable sits in its class's namespace.
    if (VirtualBaseAnalyzer.isEnabled(program)) {
        VtableVirtualBases(program, this) { registry.uniqueStructTagged(it.leafName) }.layAll()
    }
    // Once the stabs have typed what they type, the libgcc entry points among it.
    if (SjljContextAnalyzer.isEnabled(program)) {
        SjljContextAnalyzer.typeAll(program, monitor, this)
    }
}

private fun ImportContext<*>.recordHarvestCounters(harvest: Harvest, types: TypeGraph, stabs: StabReader.Result) {
    val parseErrors = diagnostics["parse-error"].toInt()
    debug("harvest-records-read", count = stabs.totalRecordCount.toLong())
    debug("harvest-records-parsed", count = (stabs.records.size - parseErrors).toLong())
    debug("harvest-functions", count = harvest.functions.size.toLong())
    val allSyms = harvest.statics
    debug("harvest-symbols", count = allSyms.size.toLong())
    debug("harvest-globals", count = allSyms.count { it.body.scope == StaticScope.GLOBAL }.toLong())
    debug("harvest-statics", count = allSyms.count { it.body.scope != StaticScope.GLOBAL }.toLong())
    debug("harvest-typeAsts", count = harvest.types.size.toLong())
    val byKind = harvest.types.values.groupingBy { it.body::class.simpleName ?: "Unknown" }.eachCount()
    for ((kind, n) in byKind.toSortedMap()) {
        debug("harvest-typeAsts-$kind", count = n.toLong())
    }
    debug("harvest-cus", count = harvest.sources.count { it.value.cu != null }.toLong())
    debug("harvest-sources", count = harvest.sources.size.toLong())
    val uniqueTypeIds = harvest.types.keys.size
    debug("harvest-typeAsts-unique-by-id", count = uniqueTypeIds.toLong())
    debug("harvest-typeAsts-dup-by-id", count = (harvest.types.size - uniqueTypeIds).toLong())
    debug("harvest-collisions-raw", count = harvest.rawCollisions.size.toLong())
    debug(
        "harvest-collisions-raw-total",
        count = harvest.rawCollisions.values.flatMap { it.values }.flatten().count().toLong(),
    )
    // Post-filter: only genuinely divergent multi-body collisions.
    debug("harvest-collisions-divergent", count = types.divergentCollisions.size.toLong())
    debug(
        "harvest-collisions-divergent-total",
        count = types.divergentCollisions.values.flatMap { it.values }.flatten().count().toLong(),
    )
}
