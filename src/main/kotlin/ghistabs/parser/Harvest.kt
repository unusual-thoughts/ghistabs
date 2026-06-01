package ghistabs.parser

import ghidra.program.model.address.Address
import ghidra.util.task.TaskMonitor
import ghistabs.diag.BookmarkSink
import ghistabs.importer.AddressResolver
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class TypeAst(val id: TypeId, val name: String, val body: TypeDecl, val cuFile: String)

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
    val cu: String,
    val locals: MutableList<LocalRecord>,
    val params: MutableList<ParamRecord>,
    val scopeBrackets: MutableList<Triple<StabType, Long, Int>>,
    var sizeBytes: Long = 0L,
)

@Serializable
data class Harvest(
    val parseErrors: Int,
    val typeAsts: List<TypeAst>,
    val symbolsByCu: Map<String, List<HarvestedSymbol>>,
    val openFunctions: List<OpenFunction>,
) {
    val typeAstsById get() = typeAsts.associateBy { it.id }
    val allHarvestedSymbols get() = symbolsByCu.values.flatten()
    val structAstsByName
        get() = typeAsts.mapNotNull { ast ->
            val body = ast.body as? TypeDecl.Struct ?: return@mapNotNull null
            ast.name to body
        }.toMap()
}

class Harvester(
    private val monitor: TaskMonitor,
    private val sink: BookmarkSink,
    private val resolver: AddressResolver,
) : LogSink {
    private val typeAsts = mutableListOf<TypeAst>()
    private val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
    private val openFunctions = mutableListOf<OpenFunction>()

    private val _includesByFile = mutableMapOf<String, IncludeContext>()
    val includesByFile: Map<String, IncludeContext> get() = _includesByFile

    override fun log(tag: String, message: String) = sink.log(tag, message)

    internal fun passA(records: List<StabRecord>): Harvest {
        var parseErrors = 0
        var currentCu = "<unknown>"
        var currentFunction: OpenFunction? = null
        var currentInclude: IncludeContext? = null
        // Allocate ONE shared HeaderRegistry for all per-CU IncludeContext instances.
        // This ensures cross-CU dedup: two CUs with the same (filename, checksum) BINCL
        // get the SAME HeaderFile instance via the shared registry.
        val sharedHeaderRegistry = HeaderRegistry()

        for ((i, rec) in records.withIndex()) {
            monitor.checkCancelled()
            monitor.incrementProgress(1)

            when (rec.type) {
                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    currentCu = rec.name
                    currentInclude = IncludeContext(rec.name, this, sharedHeaderRegistry)
                    currentInclude.openSource(rec.name)
                    _includesByFile[rec.name] = currentInclude
                }

                StabType.N_SOL if (rec.name.isNotEmpty()) -> {
                    currentCu = rec.name
                    currentInclude?.switchSource(rec.name)
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
                    currentInclude?.reMountExcluded(filename, checksum)
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
                        val decl = Parser(rec.name).parseSymbol() as? SymbolDecl.Function
                        if (decl != null) {
                            val open =
                                OpenFunction(
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
                    } catch (e: StabsParseException) {
                        parseErrors++
                        sink.log("parse-error", "@$i '${rec.name.take(80)}': ${e.message}")
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

                            else -> {}
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        sink.log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    when (val decl = Parser(rec.name).parseSymbol()) {
                        is SymbolDecl.TaggedType -> {
                            val canonicalId = currentInclude?.canonicalTypeId(decl.id) ?: decl.id
                            val canonicalBody = currentInclude?.canonicalizeTypeDecl(decl.body) ?: decl.body
                            typeAsts += TypeAst(canonicalId, decl.name, canonicalBody, currentCu)
                        }

                        is SymbolDecl.Typedef -> {
                            val canonicalId = currentInclude?.canonicalTypeId(decl.id) ?: decl.id
                            val canonicalBody = currentInclude?.canonicalizeTypeDecl(decl.body) ?: decl.body
                            typeAsts += TypeAst(canonicalId, decl.name, canonicalBody, currentCu)
                        }

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                            currentFunction?.locals?.add(LocalRecord(decl, rec.value, i))
                        }

                        is SymbolDecl.StaticVar -> {
                            // Function-scope static variables get their actual address from rec.value
                            symbolsByCu.getOrPut(currentCu) { mutableListOf() } +=
                                HarvestedSymbol(decl, rec.type, rec.value)
                        }

                        is SymbolDecl.Function, is SymbolDecl.Global, is SymbolDecl.RegParam, is SymbolDecl.StackParam,
                        -> {
                        }
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    sink.log("parse-error", "lsym @$i: ${e.message}")
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> currentFunction?.scopeBrackets?.add(
                    Triple(rec.type, rec.value, i),
                )

                // ignore N_SLINE, N_OPT, etc.
                else -> sink.log("drop-record", "dropping ${rec.type}")
            }
        }
        return Harvest(parseErrors, typeAsts, symbolsByCu, openFunctions)
    }

    private fun harvestSymbol(rec: StabRecord, currentCu: String, onError: () -> Unit) {
        try {
            val decl = Parser(rec.name).parseSymbol()
            symbolsByCu.getOrPut(currentCu) { mutableListOf() } += HarvestedSymbol(decl, rec.type, rec.value)
        } catch (e: StabsParseException) {
            onError()
            sink.log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }
}
