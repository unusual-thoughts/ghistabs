package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.importer.AddressResolver
import ghistabs.importer.ImportContext
import ghistabs.parse.*

/**
 * Harvest typed symbols and ASTs from a flat stab record stream. [cursor] holds the stream
 * position (CU, include context, source file, open function) and the N_SLINE entries; [store]
 * accumulates type ASTs. [harvest] is the dispatch loop that feeds both and collects the
 * address-bearing symbols into [staticsByCu].
 */
class Harvester(private val monitor: TaskMonitor, private val sink: DiagnosticSink, resolver: AddressResolver) :
    DiagnosticSink by sink {
    constructor(ctx: ImportContext<*>) : this(ctx.monitor, ctx, ctx.resolver)

    private val store = TypeStore(sink = sink)
    private val cursor = StabCursor(resolver, sink)
    private val staticsByCu = mutableMapOf<GhidraSourceFile, MutableList<StaticSymbol>>()
    private val constants = mutableListOf<SymbolDecl.Constant<GlobalTypeId>>()

    internal fun harvest(records: List<StabRecord>): Harvest {
        monitor.initialize(records.size.toLong(), "Stabs: harvesting")

        cursor.preSeedHeaders(records)
        for (rec in records) {
            monitor.increment()
            if (rec.desc != 0) {
                when (rec.type) {
                    StabType.N_SLINE,
                    StabType.N_FUN, // desc available on -gstabs+
                    StabType.N_PSYM, StabType.N_LSYM, StabType.N_RSYM, // params / locals
                    StabType.N_GSYM, StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM, // statics
                    -> {
                    }

                    // Other record types with non-zero desc are silently dropping a line number.
                    else -> debug(
                        "desc-dropped-${rec.type.name.removePrefix("N_").lowercase()}",
                        "desc=${rec.desc} name=${rec.name.take(40)}",
                    )
                }
            }

            when (rec.type) {
                StabType.N_SO -> cursor.sourceUnit(rec)

                // Already handled in the preSeed pass
                StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

                StabType.N_SOL if rec.name.isNotEmpty() -> cursor.switchSource(rec.name)

                StabType.N_SLINE -> cursor.lineEntry(rec)

                StabType.N_FUN if rec.name.isEmpty() -> cursor.closeFunction(rec)

                StabType.N_FUN -> parseSymbol(rec)?.also { sym ->
                    when (val decl = sym.body) {
                        is SymbolDecl.Function -> cursor.openFunction(sym.retype(decl))
                        is SymbolDecl.Static -> harvestStatic(sym.retype(decl))
                        else -> warn("unexpected-nfun", "$sym")
                    }
                }

                // N_STSYM=data, N_LCSYM=bss, N_ROSYM=rodata, N_FUN=text : n_value carries the address.
                // N_GSYM=globals: only refers by name
                StabType.N_GSYM, StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM -> parseSymbol(rec)?.also { sym ->
                    when (val decl = sym.body) {
                        is SymbolDecl.Static -> harvestStatic(sym.retype(decl))
                        else -> warn("unexpected-static", "$sym")
                    }
                }

                // Parameters and register locals
                StabType.N_PSYM, StabType.N_RSYM -> parseSymbol(rec)?.also { sym ->
                    when (val decl = sym.body) {
                        is SymbolDecl.Param -> cursor.param(sym.retype(decl))
                        is SymbolDecl.Local -> cursor.local(sym.retype(decl))
                        else -> warn("unexpected-psym-rsym", "$sym")
                    }
                }

                // Stack locals, types and constants
                StabType.N_LSYM -> parseSymbol(rec)?.also { sym ->
                    when (val decl = sym.body) {
                        // Bare `name:t(cu,n)` forward-declarations (body = self-Ref) are stored
                        // unfiltered; AstStore lets a real definition at the same id supersede them.
                        is SymbolDecl.NamedType -> store += Type(
                            cursor.cu,
                            decl.id,
                            decl.name,
                            decl.type,
                            line = sym.line,
                            sourceFile = sym.sourceFile,
                        )

                        is SymbolDecl.Local -> cursor.local(sym.retype(decl))

                        // Addressless compile-time constant — no address, so it's applied as an
                        // equate + synthetic enum catalog rather than data (see SymbolApplier).
                        is SymbolDecl.Constant -> constants += decl

                        is SymbolDecl.Function, is SymbolDecl.Param, is SymbolDecl.Static ->
                            warn("unexpected-lsym", "$sym")
                    }
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> cursor.bracket(rec)

                // Known-irrelevant for type/symbol harvesting.
                StabType.N_DSLINE, StabType.N_BSLINE, StabType.N_FLINE,
                StabType.N_OPT, StabType.N_OLEVEL, StabType.N_PARAMS, StabType.N_VERSION,
                StabType.N_MAIN, StabType.N_PC, StabType.N_M2C, StabType.N_DEFD,
                StabType.N_SSYM, StabType.N_ENDM, StabType.N_OSO, StabType.N_FNAME,
                StabType.N_EHDECL, StabType.N_CATCH, StabType.N_LENG,
                StabType.N_SCOPE, StabType.N_BCOMM, StabType.N_ECOMM, StabType.N_ECOML,
                StabType.N_ENTRY, StabType.N_MAC_DEFINE, StabType.N_MAC_UNDEF,
                // Apple/Sun cross-toolchain codes; benign on x86 PE/ELF.
                StabType.N_BNSYM, StabType.N_ENSYM, StabType.N_OBJ,
                StabType.N_ALIAS, StabType.N_NSYMS, StabType.N_NOMAP, StabType.N_PATCH,
                StabType.N_WITH,
                StabType.N_NBTEXT, StabType.N_NBDATA, StabType.N_NBBSS,
                StabType.N_NBSTS, StabType.N_NBLCS,
                -> debug("drop-record-${rec.type.name.removePrefix("N_").lowercase()}")

                // N_UNDF: cuOff/cuSize already advanced in StabReader. Empty N_SOL: nothing to switch to.
                StabType.N_UNDF, StabType.N_SOL ->
                    debug("drop-record-${rec.type.name.removePrefix("N_").lowercase()}-empty")

                // Hard signal: byte-decoder recognized but no harvesting rule. Log once per type.
                StabType.UNKNOWN -> warn(
                    "stab-unknown",
                    "rawType=0x${"%02X".format(rec.rawType)} @${rec.index} '${rec.name.take(60)}'",
                )
            }
        }

        val (openFunctions, lineEntries) = cursor.toHarvest()
        val (typeAsts, rawCollisions) = store.toHarvest()
        debug("harvest-constants", count = constants.size.toLong())

        return Harvest(typeAsts, rawCollisions, staticsByCu, openFunctions, lineEntries, constants)
    }

    private fun harvestStatic(sym: StaticSymbol) {
        staticsByCu.getOrPut(cursor.cu.identity) { mutableListOf() } += sym
    }

    private fun parseSymbol(rec: StabRecord) = when (val res = cursor.parseSymbol(rec)) {
        is ParseResult.Error -> {
            err("parse-error", "@${rec.index} '${rec.name.take(80)}': ${res.ex.message}")
            null
        }

        is ParseResult.Ok -> {
            res.trailing?.let { warn("unparsed-trailing", it) }
            res.inner.also { store.hoistSymbolDefs(it, cursor.cu) }
        }
    }
}
