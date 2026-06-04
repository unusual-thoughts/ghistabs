package ghistabs.parser

import ghidra.program.model.address.Address
import ghidra.util.task.TaskMonitor
import ghistabs.builder.TypeResolver
import ghistabs.diag.DiagnosticSink
import ghistabs.importer.AddressResolver
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class TypeAst(val id: GlobalTypeId, val name: String, val body: TypeDecl)

@Serializable
data class ParamRecord(val decl: SymbolDecl, val rawValue: Long)

/**
 * Represents a local variable record from the stabs stream.
 *
 * @property decl The parsed symbol declaration.
 * @property rawValue The raw value from the stab record (stack offset for stack locals).
 * @property recordIndex The index of this record in the stabs stream (for scope filtering).
 */
@Serializable
data class LocalRecord(val decl: SymbolDecl, val rawValue: Long, val recordIndex: Int)

@Serializable
data class HarvestedSymbol(val decl: SymbolDecl, val recordType: StabType, val rawValue: Long)

@Serializable
data class SerializableAddress(val space: String, val offset: Long) {
    constructor(addr: Address) : this(addr.addressSpace.name, addr.offset) {
        address = addr
    }

    @Transient
    lateinit var address: Address
}

@Serializable
data class OpenFunction(
    val name: String,
    val addr: SerializableAddress,
    val decl: SymbolDecl.Function,
    val cu: SourceFile.CUSource,
    val locals: MutableList<LocalRecord>,
    val params: MutableList<ParamRecord>,
    val scopeBrackets: MutableList<Triple<StabType, Long, Int>>,
    var sizeBytes: Long = 0L,
)

@Serializable
class FileResolver(private val includesByFile: Map<String, IncludeContext>) {
    fun knownFileNums(source: SourceFile) = includesByFile[source.cu]?.getAllFileNums() ?: emptySet()

    fun globalIdFor(id: LocalTypeId, source: SourceFile) =
        includesByFile[source.cu]?.sourceForFileNum(id.file)?.let { GlobalTypeId(it, id.n) }
}

@Serializable
data class Harvest(
    val parseErrors: Int,
    val typeAsts: List<TypeAst>,
    val symbolsByCu: Map<String, List<HarvestedSymbol>>,
    val openFunctions: List<OpenFunction>,
    val fileResolver: FileResolver,
    val headerRegistry: HeaderRegistry,
) {
    val allHarvestedSymbols get() = symbolsByCu.values.flatten()
    val typeResolver get() = TypeResolver(typeAsts, fileResolver)
}

class Harvester(
    private val monitor: TaskMonitor,
    private val sink: DiagnosticSink,
    private val resolver: AddressResolver,
) : DiagnosticSink by sink {
    private val typeAsts = mutableListOf<TypeAst>()
    private val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
    private val openFunctions = mutableListOf<OpenFunction>()
    private val includesByFile = mutableMapOf<String, IncludeContext>()
    private var parseErrors = 0

    // FIXME: replace with String?; and replace every "<unknown>" with null
    private lateinit var currentCu: SourceFile.CUSource
    private var currentFunction: OpenFunction? = null
    private var currentInclude: IncludeContext? = null

    // Allocate ONE shared HeaderRegistry for all per-CU IncludeContext instances.
    // This ensures cross-CU dedup: two CUs with the same (filename, checksum) BINCL
    // get the SAME HeaderFile instance via the shared registry.
    val sharedHeaderRegistry = HeaderRegistry(this)

    fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceForFileNum(id.file) ?: currentCu, id.n)

    internal fun passA(records: List<StabRecord>): Harvest {
        for ((i, rec) in records.withIndex()) {
            monitor.checkCancelled()
            monitor.incrementProgress(1)

            when (rec.type) {
                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    currentCu = SourceFile.CUSource(rec.name)
                    currentInclude = IncludeContext(rec.name, this, sharedHeaderRegistry).also {
                        includesByFile[rec.name] = it
                    }
                    if (rec.value != 0L) {
                        log("file-start", "${rec.name} starts here", address = resolver.buildAddress(rec.value))
                    }
                }

                StabType.N_SOL if (rec.name.isNotEmpty()) -> {
                }

                StabType.N_BINCL -> {
                    val filename = rec.name.ifEmpty { "<unknown>" }
                    val checksum = rec.value
                    currentInclude?.beginInclude(filename, checksum)
                }

                StabType.N_EINCL -> currentInclude?.endInclude()

                StabType.N_EXCL -> {
                    val filename = rec.name.ifEmpty { "<unknown>" }
                    val checksum = rec.value
                    currentInclude?.remount(filename, checksum)
                }

                StabType.N_FUN -> if (rec.name.isEmpty()) {
                    // End-of-function marker: rec.value = function size relative to start.
                    currentFunction?.let { it.sizeBytes = rec.value }
                    currentFunction = null
                } else {
                    val addr = resolver.buildAddress(rec.value)
                    // Pull mangled name from before the colon.
                    val mangled = rec.name.substringBefore(':')
                    resolver.recordFromStab(mangled, addr)
                    try {
                        when (val decl = Parser(rec.name).parseSymbol()) {
                            is SymbolDecl.Function -> {
                                val open = OpenFunction(
                                    name = mangled,
                                    addr = SerializableAddress(addr),
                                    decl = decl,
                                    cu = currentCu,
                                    locals = mutableListOf(),
                                    params = mutableListOf(),
                                    scopeBrackets = mutableListOf(),
                                )
                                openFunctions += open
                                currentFunction = open
                            }

                            else -> log("unexpected-nfun", "@$i: $decl")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "@$i '${rec.name.take(80)}': ${e.message}")
                    }
                }

                StabType.N_GSYM -> harvestSymbol(rec, currentCu) { parseErrors++ }

                StabType.N_STSYM, StabType.N_LCSYM -> {
                    val addr = resolver.buildAddress(rec.value)
                    val mangled = rec.name.substringBefore(':')
                    resolver.recordFromStab(mangled, addr)
                    harvestSymbol(rec, currentCu) { parseErrors++ }
                }

                StabType.N_PSYM, StabType.N_RSYM -> {
                    val open = currentFunction ?: continue
                    try {
                        when (val decl = Parser(rec.name).parseSymbol()) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam -> open.params += ParamRecord(
                                decl,
                                rec.value,
                            )

                            else -> log("unexpected-psym-rsym", "@$i: $decl")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    when (val decl = Parser(rec.name).parseSymbol()) {
                        is SymbolDecl.TaggedType -> typeAsts += TypeAst(globalIdFor(decl.id), decl.name, decl.body)
                        is SymbolDecl.Typedef -> typeAsts += TypeAst(globalIdFor(decl.id), decl.name, decl.body)

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                            currentFunction?.locals?.add(LocalRecord(decl, rec.value, i))
                        }

                        is SymbolDecl.StaticVar -> {
                            // Function-scope static variables get their actual address from rec.value
                            symbolsByCu.getOrPut(currentCu.cu) { mutableListOf() } +=
                                HarvestedSymbol(decl, rec.type, rec.value)
                        }

                        is SymbolDecl.Function, is SymbolDecl.Global, is SymbolDecl.RegParam, is SymbolDecl.StackParam,
                        -> log("unexpected-lsym", "@$i: $decl")
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    log("parse-error", "lsym @$i: ${e.message}")
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> currentFunction?.scopeBrackets?.add(
                    Triple(rec.type, rec.value, i),
                )

                // Known-irrelevant for type/symbol harvesting — bumped silently into
                // diagnostics counters by the caller (no per-record log lines, which
                // otherwise drown the log under N_SLINE @ 23k records/binary).
                StabType.N_SLINE, StabType.N_DSLINE, StabType.N_BSLINE, StabType.N_FLINE,
                StabType.N_OPT, StabType.N_OLEVEL, StabType.N_PARAMS, StabType.N_VERSION,
                StabType.N_MAIN, StabType.N_PC, StabType.N_M2C, StabType.N_DEFD,
                StabType.N_SSYM, StabType.N_ENDM, StabType.N_OSO, StabType.N_FNAME,
                StabType.N_EHDECL, StabType.N_CATCH, StabType.N_LENG,
                StabType.N_SCOPE, StabType.N_BCOMM, StabType.N_ECOMM, StabType.N_ECOML,
                StabType.N_ENTRY, StabType.N_MAC_DEFINE, StabType.N_MAC_UNDEF,
                // Apple/Sun cross-toolchain codes; benign for x86 PE / ELF.
                StabType.N_ROSYM, StabType.N_BNSYM, StabType.N_ENSYM, StabType.N_OBJ,
                StabType.N_ALIAS, StabType.N_NSYMS, StabType.N_NOMAP, StabType.N_PATCH,
                StabType.N_WITH,
                StabType.N_NBTEXT, StabType.N_NBDATA, StabType.N_NBBSS,
                StabType.N_NBSTS, StabType.N_NBLCS,
                -> log("drop-record-${rec.type.name.removePrefix("N_").lowercase()}")

                // Empty-name forms that already played their role inside StabReader:
                //   - N_UNDF: cuOff/cuSize were advanced as the record streamed by.
                //   - empty N_SO: terminates a CU; no scope state to update here.
                //   - empty N_SOL: ignored (no source filename to switch to).
                StabType.N_UNDF, StabType.N_SO, StabType.N_SOL ->
                    log("drop-record-${rec.type.name.removePrefix("N_").lowercase()}-empty")

                // Hard signal — a stab type the byte-decoder recognises but we have
                // no harvesting rule for. Log loudly, once per type, with rawType so
                // the binary's source (compiler/linker) can be identified.
                StabType.UNKNOWN -> log(
                    "stab-unknown",
                    "rawType=0x${"%02X".format(rec.rawType)} @${rec.recordIndex} '${rec.name.take(60)}'",
                )
            }
        }
        return Harvest(
            parseErrors,
            typeAsts,
            symbolsByCu,
            openFunctions,
            FileResolver(includesByFile),
            sharedHeaderRegistry,
        )
    }

    private fun harvestSymbol(rec: StabRecord, currentCu: SourceFile.CUSource, onError: () -> Unit) {
        try {
            // Canonicalise the symbol's TypeDecl exactly like N_LSYM TaggedType/Typedef
            // bodies. Without this, e.g. an N_GSYM `BranchInstructions:G(1,1103)=ar(1,4);0;15;(148,3)`
            // walks the typeAsts map looking for `(148,3)` — but `(148, 3)` is a raw
            // local file ID that has no entry: the matching typeAst was registered
            // under its canonical (48, 3) key. The global ends up untyped.
            val decl = Parser(rec.name).parseSymbol()
            symbolsByCu.getOrPut(currentCu.cu) { mutableListOf() } += HarvestedSymbol(decl, rec.type, rec.value)
        } catch (e: StabsParseException) {
            onError()
            log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }
}
