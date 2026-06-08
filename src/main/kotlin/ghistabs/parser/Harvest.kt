package ghistabs.parser

import ghidra.program.model.address.Address
import ghidra.util.task.TaskMonitor
import ghistabs.builder.TypeResolver
import ghistabs.diag.DiagnosticSink
import ghistabs.importer.AddressResolver
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class TypeAst(
    val cu: SourceFile.CUSource,
    val id: GlobalTypeId,
    val name: String,
    val body: TypeDecl<GlobalTypeId>,
) {
    val source get() = id.source
}

@Serializable
data class ParamRecord(val decl: SymbolDecl<GlobalTypeId>, val rawValue: Long)

/**
 * Represents a local variable record from the stabs stream.
 *
 * @property decl The parsed symbol declaration.
 * @property rawValue The raw value from the stab record (stack offset for stack locals).
 * @property recordIndex The index of this record in the stabs stream (for scope filtering).
 */
@Serializable
data class LocalRecord(val decl: SymbolDecl<GlobalTypeId>, val rawValue: Long, val recordIndex: Int)

@Serializable
data class HarvestedSymbol(val decl: SymbolDecl<GlobalTypeId>, val recordType: StabType, val rawValue: Long)

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
    val decl: SymbolDecl.Function<GlobalTypeId>,
    val cu: SourceFile.CUSource,
    val locals: MutableList<LocalRecord>,
    val params: MutableList<ParamRecord>,
    val scopeBrackets: MutableList<Triple<StabType, Long, Int>>,
    var sizeBytes: Long = 0L,
)

@Serializable
class FileResolver(private val includesByFile: Map<String, IncludeContext>) {
    fun knownFileNums(cu: SourceFile.CUSource) = includesByFile[cu.filename]?.getAllFileNums() ?: emptySet()

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
    val typeResolver get() = TypeResolver(typeAsts)
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
    private var currentCu: SourceFile.CUSource? = null

    private var currentFunction: OpenFunction? = null

    // Allocate ONE shared HeaderRegistry for all per-CU IncludeContext instances.
    // This ensures cross-CU dedup: two CUs with the same (filename, checksum) BINCL
    // get the SAME HeaderFile instance via the shared registry.
    val sharedHeaderRegistry = HeaderRegistry(this)

    val currentInclude get() = includesByFile[currentCu?.filename]
    fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceFor(id) ?: currentCu!!, id.n)

    internal fun preSeedHeaders(records: List<StabRecord>) {
        for (rec in records) {
            when (rec.type) {
                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    currentCu = SourceFile.CUSource(rec.name)
                    includesByFile[rec.name] = IncludeContext(SourceFile.CUSource(rec.name), this, sharedHeaderRegistry)
                }

                StabType.N_SO -> {
                    currentCu = null
                }

                StabType.N_BINCL -> currentInclude?.beginInclude(rec.name, rec.value)
                StabType.N_EINCL -> currentInclude?.endInclude()
                StabType.N_EXCL -> currentInclude?.remount(rec.name, rec.value)
                else -> {}
            }
        }
    }

    internal fun passA(records: List<StabRecord>): Harvest {
        preSeedHeaders(records)
        for ((i, rec) in records.withIndex()) {
            monitor.checkCancelled()
            monitor.incrementProgress(1)

            when (rec.type) {
                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    currentCu = SourceFile.CUSource(rec.name)
                    if (rec.value != 0L) {
                        log("file-start", "${rec.name} starts here", address = resolver.buildAddress(rec.value))
                    }
                }

                StabType.N_SO -> {
                    if (rec.value != 0L) {
                        log(
                            "file-start",
                            "${currentCu?.filename} ends here",
                            address = resolver.buildAddress(rec.value),
                        )
                    }
                    currentCu = null
                }


                }

                StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

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
                        when (val decl = parseSymbol(rec)) {
                            is SymbolDecl.Function -> {
                                val open = OpenFunction(
                                    name = mangled,
                                    addr = SerializableAddress(addr),
                                    decl = SymbolDecl.Function(decl.name, decl.isFileStatic, globalize(decl.type)),
                                    cu = currentCu!!,
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

                StabType.N_GSYM -> harvestSymbol(rec) { parseErrors++ }

                StabType.N_STSYM, StabType.N_LCSYM -> {
                    val addr = resolver.buildAddress(rec.value)
                    val mangled = rec.name.substringBefore(':')
                    resolver.recordFromStab(mangled, addr)
                    harvestSymbol(rec) { parseErrors++ }
                }

                StabType.N_PSYM, StabType.N_RSYM -> {
                    val open = currentFunction ?: continue
                    try {
                        when (val decl = parseSymbol(rec)) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam -> open.params += ParamRecord(
                                globalizeSymbol(decl),
                                rec.value,
                            )

                            is SymbolDecl.RegLocal -> {
                                open.locals.add(LocalRecord(globalizeSymbol(decl), rec.value, i))
                            }

                            else -> log("unexpected-psym-rsym", "@$i: $decl")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    when (val decl = parseSymbol(rec)) {
                        is SymbolDecl.TaggedType -> appendAsts(
                            listOf(
                                TypeAst(
                                    currentCu!!,
                                    globalIdFor(decl.id),
                                    decl.name,
                                    globalize(decl.type),
                                ),
                            ),
                        )

                        is SymbolDecl.Typedef -> appendAsts(
                            listOf(
                                TypeAst(
                                    currentCu!!,
                                    globalIdFor(decl.id),
                                    decl.name,
                                    globalize(decl.type),
                                ),
                            ),
                        )

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                            currentFunction?.locals?.add(LocalRecord(globalizeSymbol(decl), rec.value, i))
                        }

                        is SymbolDecl.StaticVar -> {
                            // Function-scope static variables get their actual address from rec.value
                            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } +=
                                HarvestedSymbol(globalizeSymbol(decl), rec.type, rec.value)
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
                //   - empty N_SOL: ignored (no source filename to switch to).
                StabType.N_UNDF, StabType.N_SOL ->
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

    private fun harvestSymbol(rec: StabRecord, onError: () -> Unit) {
        try {
            // Canonicalise the symbol's TypeDecl exactly like N_LSYM TaggedType/Typedef
            // bodies. Without this, e.g. an N_GSYM `BranchInstructions:G(1,1103)=ar(1,4);0;15;(148,3)`
            // walks the typeAsts map looking for `(148,3)` — but `(148, 3)` is a raw
            // local file ID that has no entry: the matching typeAst was registered
            // under its canonical (48, 3) key. The global ends up untyped.
            val decl = parseSymbol(rec)
            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += HarvestedSymbol(
                globalizeSymbol(decl),
                rec.type,
                rec.value,
            )
        } catch (e: StabsParseException) {
            onError()
            log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }

    fun globalizeSymbol(sym: SymbolDecl<LocalTypeId>) = when (sym) {
        is SymbolDecl.Function -> SymbolDecl.Function(sym.name, sym.isFileStatic, globalize(sym.type))
        is SymbolDecl.Global -> SymbolDecl.Global(sym.name, globalize(sym.type))
        is SymbolDecl.RegLocal -> SymbolDecl.RegLocal(sym.name, globalize(sym.type), sym.regNum)
        is SymbolDecl.RegParam -> SymbolDecl.RegLocal(sym.name, globalize(sym.type), sym.regNum)
        is SymbolDecl.StackLocal -> SymbolDecl.StackLocal(sym.name, globalize(sym.type))
        is SymbolDecl.StackParam -> SymbolDecl.StackParam(sym.name, globalize(sym.type))
        is SymbolDecl.StaticVar -> SymbolDecl.StaticVar(sym.name, globalize(sym.type), sym.isFunctionLocal)
        is SymbolDecl.TaggedType -> SymbolDecl.TaggedType(sym.name, globalIdFor(sym.id), globalize(sym.type))
        is SymbolDecl.Typedef -> SymbolDecl.Typedef(sym.name, globalIdFor(sym.id), globalize(sym.type))
    }

    fun globalize(decl: TypeDecl<LocalTypeId>): TypeDecl<GlobalTypeId> = when (decl) {
        is TypeDecl.Complex, is TypeDecl.Enum, is TypeDecl.XRef -> decl as TypeDecl<GlobalTypeId>
        is TypeDecl.Range -> TypeDecl.Range(globalIdFor(decl.of), decl.min, decl.max)
        is TypeDecl.Ref -> TypeDecl.Ref(globalIdFor(decl.id))
        is TypeDecl.Const -> TypeDecl.Const(globalize(decl.inner))
        is TypeDecl.Volatile -> TypeDecl.Volatile(globalize(decl.inner))
        is TypeDecl.WithSizeAttr -> TypeDecl.WithSizeAttr(decl.sizeBits, globalize(decl.inner))
        is TypeDecl.Pointer -> TypeDecl.Pointer(globalize(decl.pointee))
        is TypeDecl.Reference -> TypeDecl.Reference(globalize(decl.referent))
        is TypeDecl.Array -> TypeDecl.Array(globalize(decl.element), decl.length, decl.indexType?.let { globalize(it) })
        is TypeDecl.FunctionT -> TypeDecl.FunctionT(globalize(decl.ret), decl.params.map { globalize(it) })

        is TypeDecl.Method -> TypeDecl.Method(
            globalize(decl.cls),
            globalize(decl.ret),
            decl.params.map { globalize(it) },
        )

        is TypeDecl.Struct -> TypeDecl.Struct(
            decl.kind,
            decl.sizeBytes,
            decl.bases.map { BaseDecl(globalize(it.type), it.isVirtual, it.access, it.offsetBits) },
            decl.fields.map { FieldDecl(it.name, globalize(it.type), it.offsetBits, it.sizeBits, it.isStatic) },
            decl.methods.map {
                MethodDecl(
                    it.name,
                    it.mangled,
                    globalize(it.signature),
                    it.access,
                    it.virt,
                    it.isConst,
                    it.isVolatile,
                    it.vtableOffsetBits,
                )
            },
            decl.hasVTablePointerMarker,
            decl.vtableTargetTypeId?.let { globalIdFor(it) },
        )

        is TypeDecl.InlineDef -> TypeDecl.InlineDef(globalIdFor(decl.id), globalize(decl.body))
    }

    fun walkDefinitions(decl: TypeDecl<LocalTypeId>): List<TypeAst> = when (decl) {
        is TypeDecl.Complex, is TypeDecl.Enum, is TypeDecl.Range, is TypeDecl.Ref, is TypeDecl.XRef -> listOf()
        is TypeDecl.Const -> walkDefinitions(decl.inner)
        is TypeDecl.Volatile -> walkDefinitions(decl.inner)
        is TypeDecl.WithSizeAttr -> walkDefinitions(decl.inner)
        is TypeDecl.Pointer -> walkDefinitions(decl.pointee)
        is TypeDecl.Reference -> walkDefinitions(decl.referent)
        is TypeDecl.Array -> walkDefinitions(decl.element) + (decl.indexType?.let { walkDefinitions(it) } ?: listOf())
        is TypeDecl.FunctionT -> decl.params.flatMap { walkDefinitions(it) } + walkDefinitions(decl.ret)

        is TypeDecl.Method -> decl.params.flatMap { walkDefinitions(it) } + walkDefinitions(decl.ret) + walkDefinitions(
            decl.cls,
        )

        is TypeDecl.Struct -> decl.bases.flatMap { walkDefinitions(it.type) } +
            decl.fields.flatMap { walkDefinitions(it.type) } +
            decl.methods.flatMap { walkDefinitions(it.signature) }

        is TypeDecl.InlineDef if decl.body is TypeDecl.XRef -> {
            log("dropping-fwd-xref", "${decl.id}")
            listOf()
        }

        is TypeDecl.InlineDef -> listOf(
            TypeAst(
                currentCu!!,
                globalIdFor(decl.id),
                "unnamed_${decl.id}",
                globalize(decl.body),
            ),
        )
    }

    fun appendAsts(asts: List<TypeAst>) {
        val existing = typeAsts.groupBy { it.id }
        val new = asts.groupBy { it.id }
        val collisions = existing.keys.intersect(new.keys)
        if (collisions.isNotEmpty()) {
            for (id in collisions) {
                val exHash = existing[id]!!.associate { it.name to it.body.hashCode() }
                val newHash = new[id]!!.associate { it.name to it.body.hashCode() }
                if (exHash == newHash) {
                    log("ast-id-collision-same-hash", "$exHash == $newHash")
                } else {
                    log("ast-id-collision", "$exHash != $newHash")
                }
            }
        }
        typeAsts += asts.filter { !collisions.contains(it.id) }
    }

    fun parseSymbol(rec: StabRecord) = Parser(rec.name).parseSymbol().also { appendAsts(walkDefinitions(it.type)) }
}
