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
 * address-bearing symbols into [symbolsByCu].
 */
class Harvester(private val monitor: TaskMonitor, sink: DiagnosticSink, resolver: AddressResolver) :
    DiagnosticSink by sink {
    constructor(ctx: ImportContext<*>) : this(ctx.monitor, ctx, ctx.resolver)

    private val store = AstStore(sink = sink)
    private val cursor = StabCursor(resolver, sink)
    private val symbolsByCu = mutableMapOf<String, MutableList<SymbolRecord>>()
    private val constants = mutableListOf<SymbolDecl.Constant<GlobalTypeId>>()
    private var parseErrors = 0

    internal fun harvest(records: List<StabRecord>): Harvest {
        monitor.initialize(records.size.toLong(), "Stabs: harvesting")

        cursor.preSeedHeaders(records)
        for ((i, rec) in records.withIndex()) {
            monitor.increment()
            if (rec.desc != 0) {
                when (rec.type) {
                    StabType.N_FUN, StabType.N_SLINE, StabType.N_LSYM,
                    StabType.N_PSYM, StabType.N_RSYM,
                    StabType.N_GSYM, StabType.N_LCSYM, StabType.N_STSYM, StabType.N_ROSYM,
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

                StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

                StabType.N_SOL if rec.name.isNotEmpty() -> cursor.switchSource(rec.name)

                StabType.N_SLINE -> cursor.lineEntry(rec)

                StabType.N_FUN if rec.name.isEmpty() -> cursor.closeFunction(rec)
                StabType.N_FUN -> try {
                    val sym = parseSymbol(rec)
                    when (sym.body) {
                        is SymbolDecl.Function -> cursor.openFunction(rec, sym.body)

                        is SymbolDecl.StaticVar -> harvestSymbol(rec)

                        else -> warn("unexpected-nfun", "$sym")
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    warn("parse-error", "@$i '${rec.name.take(80)}': ${e.message}")
                }

                StabType.N_GSYM -> harvestSymbol(rec)

                // Address-bearing statics: N_STSYM=data, N_LCSYM=bss, N_ROSYM=rodata
                // (stabs.texinfo §"Static Variables"). Section differs; n_value carries the address.
                StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM -> harvestSymbol(rec)

                StabType.N_PSYM, StabType.N_RSYM -> {
                    val open = cursor.currentFunction ?: continue
                    try {
                        val sym = parseSymbol(rec)
                        when (sym.body) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam -> open.params += sym
                            is SymbolDecl.RegLocal -> open.locals += sym
                            else -> warn("unexpected-psym-rsym", "$sym")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        warn("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    val sym = parseSymbol(rec)
                    when (val decl = sym.body) {
                        // Bare `name:t(cu,n)` forward-declarations (body = self-Ref) are stored
                        // unfiltered; AstStore lets a real definition at the same id supersede them.
                        is SymbolDecl.NamedType -> store += TypeAst(
                            cursor.cu,
                            decl.id,
                            decl.name,
                            decl.type,
                            declLine = sym.declLine,
                            declSourceFile = sym.sourceFile,
                        )

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal ->
                            cursor.currentFunction?.locals?.add(sym)

                        // Function-scope statics get their address from rec.value.
                        is SymbolDecl.StaticVar -> record(sym)

                        // Addressless compile-time constant — no address, so it's applied as an
                        // equate + synthetic enum catalog rather than data (see SymbolApplier).
                        is SymbolDecl.Constant -> constants += decl

                        is SymbolDecl.Function, is SymbolDecl.Global, is SymbolDecl.RegParam, is SymbolDecl.StackParam,
                        -> warn("unexpected-lsym", "$sym")
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    warn("parse-error", "lsym @$i: ${e.message}")
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> cursor.bracket(rec, i)

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

                // Hard signal: byte-decoder recognised but no harvesting rule. Log once per type.
                StabType.UNKNOWN -> warn(
                    "stab-unknown",
                    "rawType=0x${"%02X".format(rec.rawType)} @${rec.index} '${rec.name.take(60)}'",
                )
            }
        }

        val (openFunctions, lineEntries) = cursor.toHarvest()
        val (typeAsts, rawCollisions) = store.toHarvest()
        debug("harvest-constants", count = constants.size.toLong())

        return Harvest(typeAsts, parseErrors, rawCollisions, symbolsByCu, openFunctions, lineEntries, constants)
    }

    private fun record(sym: SymbolRecord) {
        symbolsByCu.getOrPut(cursor.cu.filename) { mutableListOf() } += sym
    }

    private fun harvestSymbol(rec: StabRecord) {
        try {
            record(parseSymbol(rec))
        } catch (e: StabsParseException) {
            parseErrors++
            warn("parse-error", "@${rec.index} '${rec.name.take(80)}': ${e.message}")
        }
    }

    private fun parseSymbol(rec: StabRecord) = SymbolRecord(
        rec,
        Parser(rec.name, cursor).parseSymbol().globalize(cursor),
        cursor.lineSource,
        cursor.currentFunction?.name,
    ).also {
        store.hoistSymbolDefs(it, cursor.cu)
    }
}
