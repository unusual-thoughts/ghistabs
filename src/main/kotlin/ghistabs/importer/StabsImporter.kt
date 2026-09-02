package ghistabs.importer

import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.Harvest
import ghistabs.harvest.Harvester
import ghistabs.importer.ImportOptions.Companion.markStabsTypedefsShortened
import ghistabs.index.SourceHints
import ghistabs.index.SourceIndex
import ghistabs.index.TypeGraph
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.materializeAll
import ghistabs.materialize.reportConflictDelta
import ghistabs.materialize.reportSurvivingPlaceholders
import ghistabs.parse.StabReader
import ghistabs.parse.StaticScope
import ghistabs.runTransaction
import java.nio.file.Path

/**
 * Orchestrates the stabs import pipeline: harvest records → materialize types → apply symbols.
 * The heavy lifting lives in [Harvester] (harvest), [DataTypeRegistry] (materialize) and
 * [SymbolApplier] (apply); this class only sequences them and tallies the result.
 */
class StabsImporter(internal val ctx: ImportContext<*>) : DiagnosticSink by ctx {
    fun run(): ImportResult {
        val reader = StabReader.fromProgram(ctx.program)
        if (reader == null) {
            log("no-stabs", "No .stab/.stabstr block found; skipping import.")
            ctx.diagnostics.writeSummary(ctx.terminal)
            return ImportResult()
        }

        return runOnRecords(reader.readAll(ctx.monitor))
    }

    internal fun runOnRecords(stabs: StabReader.Result): ImportResult {
        // Pass A — parse + harvest
        val harvest = ctx.harvester().harvest(stabs.records)
        // The three indexes over it, constructed together and handed out by half: resolution to the
        // passes that resolve, folding to the ones that render, the vote to the one that places.
        val types = TypeGraph(harvest, ctx)
        val sources = SourceIndex(harvest, ctx.options.foldSources, ctx)
        val hints = SourceHints(harvest, types, sources, ctx)
        recordHarvestCounters(harvest, types, stabs)

        // Pass B — materialize types
        val registry = DataTypeRegistry(ctx.dtm, ctx, ctx.diagnostics, harvest, types, hints, ctx.monitor)
        val materialized = ctx.program.runTransaction("Stabs: materialize types") {
            registry.materializeAll().also {
                if (ctx.options.shortenTypedefs) ctx.typedefShortener(registry.stubNames).apply()
                // The render spells types to match the decompiler, and it may run much later from the GUI
                // against analyzer options that have since been toggled — so record what actually happened.
                ctx.program.markStabsTypedefsShortened(ctx.options.shortenTypedefs)
            }
        }

        // Pass C — apply symbols, then build classes/vtables, demangle, and replace demangler stubs
        val applied = ctx.program.runTransaction("Stabs: apply symbols") {
            SymbolApplier(ctx, harvest, registry).run {
                ImportResult.ApplyResults(
                    functions = applyAllFunctions(),
                    globals = applyAllGlobals(),
                    constants = applyAllConstants(),
                    staticMembers = applyAllStaticMembers(),
                    classes = when {
                        ctx.options.buildClasses -> ctx.classBuilder(registry, types).buildAll()
                        else -> 0
                    },
                )
            }.also {
                ctx.demanglerReplacer(registry).replace()
            }
        }

        // Pass D — publish the line map, then point it at local sources if any root was given
        val sourceMapEntries = ctx.program.runTransaction("Stabs: publish source map") {
            SourceMapApplier(ctx, harvest, sources).apply()
        }
        ctx.program.applySourceRoots(ctx.options.sourceRoots.map(Path::of), ctx)

        ctx.analyzeDataCoverage()
        registry.reportSurvivingPlaceholders()
        registry.reportConflictDelta()
        ctx.diagnostics.writeSummary(ctx.terminal)
        val parseErrors = ctx.diagnostics["parse-error"].toInt()

        return ImportResult(
            parsed = ImportResult.ParseResults(stabs, parseErrors),
            types = ImportResult.TypeResults(harvested = harvest.types.size, materialized = materialized),
            applied = applied,
            sourceMapEntries = sourceMapEntries,
            artifacts = ImportArtifacts(registry, types, sources, hints, harvest, stabs.records),
        )
    }

    private fun recordHarvestCounters(harvest: Harvest, types: TypeGraph, stabs: StabReader.Result) {
        val parseErrors = ctx.diagnostics["parse-error"].toInt()
        debug("harvest-records-read", count = stabs.totalRecordCount.toLong())
        debug("harvest-records-parsed", count = (stabs.records.size - parseErrors).toLong())
        debug("harvest-functions", count = harvest.functions.size.toLong())
        val allSyms = harvest.statics
        debug("harvest-symbols", count = allSyms.size.toLong())
        debug(
            "harvest-globals",
            count = allSyms.count { it.body.scope == StaticScope.GLOBAL }.toLong(),
        )
        debug(
            "harvest-statics",
            count = allSyms.count { it.body.scope != StaticScope.GLOBAL }.toLong(),
        )
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
}
