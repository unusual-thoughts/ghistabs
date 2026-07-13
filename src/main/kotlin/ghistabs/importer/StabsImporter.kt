package ghistabs.importer

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.analyzeDataCoverage
import ghistabs.harvest.Harvest
import ghistabs.harvest.Harvester
import ghistabs.harvest.TypeResolver
import ghistabs.materialize.ClassBuilder
import ghistabs.materialize.TypeRegistry
import ghistabs.materialize.TypedefShortener
import ghistabs.parse.StabReader
import ghistabs.parse.SymbolDecl
import ghistabs.runTransaction

/**
 * Orchestrates the stabs import pipeline: harvest records → materialise types → apply symbols.
 * The heavy lifting lives in [Harvester] (harvest), [TypeRegistry] (materialise) and
 * [SymbolApplier] (apply); this class only sequences them and tallies the result.
 */
class StabsImporter(internal val ctx: ImportContext<*>) : DiagnosticSink by ctx {
    fun run(): PassResult {
        val reader = StabReader.fromProgram(ctx.program)
        if (reader == null) {
            log("no-stabs", "No .stab/.stabstr block found; skipping import.")
            ctx.diagnostics.writeSummary(ctx.terminal)
            return PassResult()
        }

        return runOnRecords(reader.readAll())
    }

    internal fun runOnRecords(stabs: StabReader.Result): PassResult {
        // Pass A — parse + harvest
        val harvest = Harvester(ctx).harvest(stabs.records)
        // Resolver: by-name/by-base-tag indices, source folding, divergent-collision
        // filtering. Every cross-CU lookup downstream goes through this.
        val typeResolver = TypeResolver(harvest, ctx.options.foldSources, ctx)
        recordHarvestCounters(harvest, typeResolver, stabs)

        // Pass B — materialise types
        val typeRegistry = TypeRegistry(ctx.dtm, ctx, ctx.diagnostics, harvest, typeResolver, ctx.monitor)
        ctx.program.runTransaction("Stabs: materialise types") {
            typeRegistry.materialiseAll()
            if (ctx.options.shortenTypedefs) TypedefShortener(ctx.dtm, ctx).apply()
        }

        // Pass C — apply symbols, then build classes/vtables, demangle, and replace demangler stubs
        var classes = 0
        var constants = 0
        val (functions, globals) = ctx.program.runTransaction("Stabs: apply symbols") {
            val applier = SymbolApplier(ctx, harvest, typeRegistry)
            val functions = applier.applyAllFunctions()
            val globals = applier.applyAllGlobals()
            constants = applier.applyAllConstants()
            if (ctx.options.applyVtables) {
                classes = ClassBuilder(typeRegistry, harvest, typeResolver, ctx).buildAll()
            }
            DemanglerReplacer(ctx, typeRegistry).replace()
            functions to globals
        }

        ctx.analyzeDataCoverage()
        typeRegistry.reportSurvivingPlaceholders()
        ctx.diagnostics.writeSummary(ctx.terminal)
        ctx.typeRegistry = typeRegistry
        ctx.typeResolver = typeResolver

        return PassResult(
            recordsRead = stabs.totalRecordCount,
            recordsParsed = stabs.records.size - harvest.parseErrors,
            parseErrors = harvest.parseErrors,
            typesMaterialised = harvest.typeAsts.size,
            functionsApplied = functions,
            globalsApplied = globals,
            classesApplied = classes,
            constantsApplied = constants,
        )
    }

    private fun recordHarvestCounters(harvest: Harvest, resolver: TypeResolver, stabs: StabReader.Result) {
        debug("harvest-records-read", count = stabs.totalRecordCount.toLong())
        debug("harvest-records-parsed", count = (stabs.records.size - harvest.parseErrors).toLong())
        debug("harvest-parse-errors", count = harvest.parseErrors.toLong())
        debug("harvest-functions", count = harvest.openFunctions.size.toLong())
        val allSyms = harvest.symbolsByCu.values.flatten()
        debug("harvest-symbols", count = allSyms.size.toLong())
        debug("harvest-globals", count = allSyms.count { it.body is SymbolDecl.Global }.toLong())
        debug("harvest-statics", count = allSyms.count { it.body is SymbolDecl.StaticVar }.toLong())
        debug("harvest-typeAsts", count = harvest.typeAsts.size.toLong())
        val byKind = harvest.typeAsts.values.groupingBy { it.body::class.simpleName ?: "Unknown" }.eachCount()
        for ((kind, n) in byKind.toSortedMap()) {
            debug("harvest-typeAsts-$kind", count = n.toLong())
        }
        debug("harvest-cus", count = harvest.symbolsByCu.size.toLong())
        val uniqueTypeIds = harvest.typeAsts.keys.size
        debug("harvest-typeAsts-unique-by-id", count = uniqueTypeIds.toLong())
        debug("harvest-typeAsts-dup-by-id", count = (harvest.typeAsts.size - uniqueTypeIds).toLong())
        debug("harvest-collisions-raw", count = harvest.rawCollisions.size.toLong())
        debug(
            "harvest-collisions-raw-total",
            count = harvest.rawCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
        // Post-filter: only genuinely divergent multi-body collisions.
        debug("harvest-collisions-divergent", count = resolver.divergentCollisions.size.toLong())
        debug(
            "harvest-collisions-divergent-total",
            count = resolver.divergentCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
    }
}
