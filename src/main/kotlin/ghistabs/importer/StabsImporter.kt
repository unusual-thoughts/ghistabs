package ghistabs.importer

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.analyzeDataCoverage
import ghistabs.harvest.Harvest
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.Harvester
import ghistabs.materialize.*
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.StabReader
import ghistabs.parse.StaticScope
import ghistabs.parse.SymbolDecl
import ghistabs.runTransaction

/**
 * Orchestrates the stabs import pipeline: harvest records → materialize types → apply symbols.
 * The heavy lifting lives in [Harvester] (harvest), [DataTypeRegistry] (materialize) and
 * [SymbolApplier] (apply); this class only sequences them and tallies the result.
 */
class StabsImporter(internal val ctx: ImportContext<*>) : DiagnosticSink by ctx {
    /** The materialized state, set once [runOnRecords] completes; null after a no-stabs [run]. */
    internal lateinit var artifacts: ImportArtifacts
        private set

    fun run(): PassResult {
        val reader = StabReader.fromProgram(ctx.program)
        if (reader == null) {
            log("no-stabs", "No .stab/.stabstr block found; skipping import.")
            ctx.diagnostics.writeSummary(ctx.terminal)
            return PassResult.NOTHING
        }

        return runOnRecords(reader.readAll())
    }

    internal fun runOnRecords(stabs: StabReader.Result): PassResult {
        // Pass A — parse + harvest
        val harvest = Harvester(ctx).harvest(stabs.records)
        // Resolver: by-name/by-base-tag indices, source folding, divergent-collision
        // filtering. Every cross-CU lookup downstream goes through this.
        val index = HarvestIndex(harvest, ctx.options.foldSources, ctx)
        recordHarvestCounters(harvest, index, stabs)

        // Pass B — materialize types
        val registry = DataTypeRegistry(ctx.dtm, ctx, ctx.diagnostics, harvest, index, ctx.monitor)
        ctx.program.runTransaction("Stabs: materialize types") {
            registry.materializeAll()
            if (ctx.options.shortenTypedefs) TypedefShortener(ctx.dtm, ctx).apply()
        }

        // Pass C — apply symbols, then build classes/vtables, demangle, and replace demangler stubs
        var classes = 0
        var constants = 0
        var staticMembers = 0
        val (functions, globals) = ctx.program.runTransaction("Stabs: apply symbols") {
            val applier = SymbolApplier(ctx, harvest, registry)
            val functions = applier.applyAllFunctions()
            val globals = applier.applyAllGlobals()
            constants = applier.applyAllConstants()
            staticMembers = applier.applyAllStaticMembers()
            if (ctx.options.buildClasses) {
                classes = ClassBuilder(registry, index, ctx).buildAll()
            }
            DemanglerReplacer(ctx, registry).replace()
            functions to globals
        }

        ctx.analyzeDataCoverage()
        registry.reportSurvivingPlaceholders()
        registry.reportConflictDelta()
        ctx.diagnostics.writeSummary(ctx.terminal)
        artifacts = ImportArtifacts(registry, index, harvest, stabs.records)
        val parseErrors = ctx.diagnostics["parse-error"].toInt()

        return PassResult(
            recordsRead = stabs.totalRecordCount,
            recordsParsed = stabs.records.size - parseErrors,
            parseErrors = parseErrors,
            typesMaterialized = harvest.types.size,
            functionsApplied = functions,
            globalsApplied = globals,
            classesApplied = classes,
            constantsApplied = constants,
            staticMembersApplied = staticMembers,
        )
    }

    private fun recordHarvestCounters(harvest: Harvest, index: HarvestIndex, stabs: StabReader.Result) {
        val parseErrors = ctx.diagnostics["parse-error"].toInt()
        debug("harvest-records-read", count = stabs.totalRecordCount.toLong())
        debug("harvest-records-parsed", count = (stabs.records.size - parseErrors).toLong())
        debug("harvest-functions", count = harvest.functions.size.toLong())
        val allSyms = harvest.symbolsByCu.values.flatten()
        debug("harvest-symbols", count = allSyms.size.toLong())
        debug(
            "harvest-globals",
            count = allSyms.map { it.body }.filterIsInstance<SymbolDecl.Static<GlobalTypeId>>()
                .count { it.scope == StaticScope.GLOBAL }.toLong(),
        )
        debug(
            "harvest-statics",
            count = allSyms.map { it.body }.filterIsInstance<SymbolDecl.Static<GlobalTypeId>>()
                .count { it.scope != StaticScope.GLOBAL }.toLong(),
        )
        debug("harvest-typeAsts", count = harvest.types.size.toLong())
        val byKind = harvest.types.values.groupingBy { it.body::class.simpleName ?: "Unknown" }.eachCount()
        for ((kind, n) in byKind.toSortedMap()) {
            debug("harvest-typeAsts-$kind", count = n.toLong())
        }
        debug("harvest-cus", count = harvest.symbolsByCu.size.toLong())
        val uniqueTypeIds = harvest.types.keys.size
        debug("harvest-typeAsts-unique-by-id", count = uniqueTypeIds.toLong())
        debug("harvest-typeAsts-dup-by-id", count = (harvest.types.size - uniqueTypeIds).toLong())
        debug("harvest-collisions-raw", count = harvest.rawCollisions.size.toLong())
        debug(
            "harvest-collisions-raw-total",
            count = harvest.rawCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
        // Post-filter: only genuinely divergent multi-body collisions.
        debug("harvest-collisions-divergent", count = index.divergentCollisions.size.toLong())
        debug(
            "harvest-collisions-divergent-total",
            count = index.divergentCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
    }
}
