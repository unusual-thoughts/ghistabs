package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.parse.*

/**
 * Harvest typed symbols and ASTs from a flat stab record stream. [cursor] holds the stream
 * position (CU, include context, source file, open function) and the N_SLINE entries; [store]
 * accumulates type ASTs. [harvest] is the dispatch loop that feeds both and collects the
 * address-bearing symbols into [staticsByCu].
 */
class Harvester(private val monitor: TaskMonitor, private val sink: DiagnosticSink, resolver: AddressResolver) :
    DiagnosticSink by sink {

    private val store = TypeStore(sink = sink)
    private val cursor = StabCursor(resolver, sink)
    private val staticsByCu = mutableMapOf<GhidraSourceFile, MutableList<StaticSymbol>>()
    private val constants = mutableMapOf<GhidraSourceFile, MutableList<SymbolDecl.Constant<GlobalTypeId>>>()

    /** Make sure we didn't drop `desc` or `value` fields */
    private fun StabRecord.checkDroppedFields() {
        if (desc != 0) {
            when (type) {
                StabType.N_UNDF, // symbol count
                StabType.N_SLINE,
                StabType.N_SO, // source language, read into CuContext.language
                StabType.N_FUN, // desc available on -gstabs+
                StabType.N_PSYM, StabType.N_LSYM, StabType.N_RSYM, // params / locals
                StabType.N_GSYM, StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM, // statics
                -> {}

                // Other record types with non-zero desc are dropping a line number.
                else -> debug("desc-dropped-${typeRepr()}", "$this")
            }
        }

        if (value != 0L) {
            when (type) {
                StabType.N_UNDF, // string table byte size
                StabType.N_SO, StabType.N_SOL, // file start/end address
                StabType.N_BINCL, StabType.N_EXCL, // checksum
                StabType.N_LBRAC, StabType.N_RBRAC, // address
                StabType.N_SLINE, // address
                StabType.N_FUN, // desc available on -gstabs+
                StabType.N_PSYM, StabType.N_LSYM, StabType.N_RSYM, // stack offset or register number
                StabType.N_GSYM, StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM, // statics
                -> {}

                // Other record types with non-zero value are dropping an address or other data
                else -> warn("value-dropped-${typeRepr()}", "$this")
            }
        }

        if (other != 0.toUByte()) {
            warn("other-dropped-${typeRepr()}", "$this")
        }
    }

    private fun StabRecord.harvest() = when (type) {
        StabType.N_SO -> cursor.sourceUnit(this)

        // Already handled in the preSeed pass
        StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

        StabType.N_SOL -> cursor.switchSource(this)

        StabType.N_SLINE -> cursor.lineEntry(this)

        StabType.N_FUN if name.isEmpty() -> cursor.closeFunction(this)

        StabType.N_FUN -> harvestSymbol()?.also { sym ->
            when (val decl = sym.body) {
                is SymbolDecl.Function -> cursor.openFunction(sym.retype(decl))
                is SymbolDecl.Static -> harvestStatic(sym.retype(decl))
                else -> warn("unexpected-nfun", "$sym")
            }
        }

        // N_STSYM=data, N_LCSYM=bss, N_ROSYM=rodata, N_FUN=text : n_value carries the address.
        // N_GSYM=globals: only refers by name
        StabType.N_GSYM, StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM -> harvestSymbol()?.also { sym ->
            when (val decl = sym.body) {
                is SymbolDecl.Static -> harvestStatic(sym.retype(decl))
                else -> warn("unexpected-static", "$sym")
            }
        }

        // Parameters and register locals
        StabType.N_PSYM, StabType.N_RSYM -> harvestSymbol()?.also { sym ->
            when (val decl = sym.body) {
                is SymbolDecl.Param -> cursor.param(sym.retype(decl))
                is SymbolDecl.Local -> cursor.local(sym.retype(decl))
                else -> warn("unexpected-psym-rsym", "$sym")
            }
        }

        // Stack locals, types and constants
        StabType.N_LSYM -> harvestSymbol()?.also { sym ->
            when (val decl = sym.body) {
                // Bare `name:t(cu,n)` forward-declarations (body = self-Ref) are stored
                // unfiltered; AstStore lets a real definition at the same id supersede them.
                is SymbolDecl.NamedType -> store += Type(
                    cursor.cu,
                    decl.id,
                    // gcc gives a tagless, typedef-less `enum { A, B };` a single-space symbol name,
                    // which the parser normalizes to ""
                    decl.name.ifEmpty { null },
                    decl.type,
                    line = sym.line,
                    sourceFile = sym.sourceFile,
                )

                is SymbolDecl.Local -> cursor.local(sym.retype(decl))

                // Addressless compile-time constant — no address, so it's applied as an
                // equate + synthetic enum catalog rather than data (see SymbolApplier).
                is SymbolDecl.Constant -> constants.getOrPut(cursor.cu.identity) { mutableListOf() } += decl

                is SymbolDecl.Function, is SymbolDecl.Param, is SymbolDecl.Static ->
                    warn("unexpected-lsym", "$sym")
            }
        }

        StabType.N_LBRAC, StabType.N_RBRAC -> cursor.bracket(this)

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
        -> debug("drop-record-${typeRepr()}", "$this")

        // N_UNDF: cuOff/cuSize already advanced in StabReader.
        StabType.N_UNDF -> debug("drop-record-undf-empty")

        // Hard signal: byte-decoder recognized but no harvesting rule. Log once per type.
        StabType.UNKNOWN -> warn("stab-unknown", "$this")
    }

    internal fun harvest(records: List<StabRecord>): Harvest {
        monitor.initialize(records.size.toLong(), "Stabs: harvesting")

        cursor.preSeedHeaders(records)
        for (rec in records) {
            monitor.increment()
            rec.harvest()
            rec.checkDroppedFields()
        }

        val (lineEntries, cus, textRanges) = cursor.toHarvest()
        val (typeAsts, rawCollisions) = store.toHarvest()
        debug("harvest-constants", count = constants.values.sumOf { it.size }.toLong())
        debug("harvest-text-ranges", count = textRanges.size.toLong())

        // `cus` alone decides CU-ness: statics and constants key off `cursor.cu`, which `preSeedHeaders`
        // built a CuContext for from the same N_SO record, so their keys cannot reach outside it.
        return Harvest(
            typeAsts,
            rawCollisions,
            (cus.keys + lineEntries.keys).associateWith { file ->
                SourceHarvest(
                    lineEntries[file].orEmpty(),
                    cus[file]?.let {
                        CompilationUnit(
                            staticsByCu[file].orEmpty(),
                            it.functions,
                            constants[file].orEmpty(),
                            it.range,
                            it.language,
                        )
                    },
                )
            },
            textRanges,
        )
    }

    private fun harvestStatic(sym: StaticSymbol) {
        staticsByCu.getOrPut(cursor.cu.identity) { mutableListOf() } += sym
    }

    /** Parses a symbol record then hoist any contained inline type definitions */
    private fun StabRecord.harvestSymbol() = when (val res = cursor.parseSymbol(this)) {
        is ParseResult.Error -> {
            err("parse-error", "@$index '${name.take(80)}': ${res.ex.message}")
            null
        }

        is ParseResult.Ok -> {
            res.trailing?.let { warn("unparsed-trailing", it) }
            res.inner.also { store.hoistInlineDefs(it, cursor.cu) }
        }
    }
}
