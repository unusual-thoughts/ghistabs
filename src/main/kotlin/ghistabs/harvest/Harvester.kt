package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.importer.AddressResolver
import ghistabs.parse.*

/**
 * Harvests typed symbols and type ASTs from a flat stab record stream.
 *
 * Two-pass pipeline:
 *  1. [preSeedHeaders] — scans for N_SO / N_BINCL / N_EINCL / N_EXCL to populate
 *     per-CU [IncludeContext] instances before any type symbols are processed.
 *  2. [passA] — main pass; dispatches on record type to populate [typeAsts],
 *     [symbolsByCu], and [openFunctions], calling [globalize] and [appendAsts]
 *     for each parsed symbol.
 *
 * Shared-registry invariant: the [HeaderRegistry] passed to each [IncludeContext]
 * is shared across all CUs. Two CUs that BINCL/EXCL the same (filename, checksum)
 * therefore receive the same [ghistabs.parse.HeaderFile] instance, making their [ghistabs.parse.GlobalTypeId]s
 * identical for header-attributed types (see stabs-canonicalization.md §3).
 */
class Harvester(
    private val monitor: TaskMonitor,
    private val sink: DiagnosticSink,
    private val resolver: AddressResolver,
) : DiagnosticSink by sink,
    Globalizer {
    private val typeAsts = mutableMapOf<GlobalTypeId, TypeAst>()
    private val collidingAsts = mutableMapOf<GlobalTypeId, MutableMap<String, MutableSet<TypeDecl<GlobalTypeId>>>>()
    private val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
    private val openFunctions = mutableListOf<OpenFunction>()
    private val includesByFile = mutableMapOf<String, IncludeContext>()
    private var parseErrors = 0

    private var currentCu: SourceFile.CUSource? = null
    private var currentFunction: OpenFunction? = null

    /**
     * Pending compilation-directory from a trailing-slash N_SO record.
     * Per stabs.texinfo §"Source Files": gcc / SunOS /bin/cc emit two
     * N_SO records back-to-back — the first is the compilation directory
     * (ends in `/`), the second is the source filename. We pair them
     * here so the filename's CUSource carries the directory. cfront may
     * emit additional N_SO entries for nonexistent source files after
     * the real one; they "contain no useful information" per the spec,
     * so we ignore further N_SOs until the empty-name end-of-CU marker.
     */
    private var pendingDirectory: String? = null
    private var currentCuFinalised = false

    /**
     * Current source filename for N_SLINE attribution. N_SOL (non-empty)
     * switches it; an N_SO end-of-CU marker resets it to null. When null
     * but inside a CU, [currentCu] supplies the default. Stabs.texinfo:
     * "An N_SOL record specifies that subsequent N_SLINE records refer to
     * the source file named." Without it, lines inside `#include`'d
     * headers would all be filed under the enclosing CU.
     */
    private var currentSourceForLines: String? = null
    private val lineEntriesByFile = mutableMapOf<String, MutableList<LineEntry>>()

    /**
     * gcc 12 (and other modern ELF emitters) omit the empty-name N_FUN
     * end marker — they delimit the function's address range with the
     * outermost N_RBRAC instead. When we're about to swap functions
     * (new named N_FUN or end-of-CU N_SO), compute the previous
     * function's size from its scope brackets if no explicit
     * end-of-function record set it.
     */
    private fun finaliseGcc12FunctionSize() {
        val f = currentFunction ?: return
        if (f.sizeBytes != 0L) return
        val rbracs = f.scopeBrackets.filter { it.first == StabType.N_RBRAC }
        if (rbracs.isEmpty()) return
        // N_RBRAC values follow the same absolute-vs-function-relative
        // convention as N_SLINE: large = absolute text address, small =
        // function-relative offset.
        val funcStart = f.addr.address.offset
        val maxRbrac = rbracs.maxOf { it.second }
        f.sizeBytes = if (maxRbrac > funcStart) maxRbrac - funcStart else maxRbrac
    }

    // Allocate ONE shared HeaderRegistry for all per-CU IncludeContext instances.
    // This ensures cross-CU dedup: two CUs with the same (filename, checksum) BINCL
    // get the SAME HeaderFile instance via the shared registry.
    val sharedHeaderRegistry = HeaderRegistry(this)

    val currentInclude get() = includesByFile[currentCu?.filename]
    override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceFor(id) ?: currentCu!!, id.n)

    internal fun preSeedHeaders(records: List<StabRecord>) {
        for (rec in records) {
            when (rec.type) {
                StabType.N_SO if (rec.name.endsWith('/')) -> {
                    pendingDirectory = rec.name
                    currentCuFinalised = false
                }

                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    if (currentCuFinalised) continue // cfront extra N_SO — ignore
                    val cu = SourceFile.CUSource(rec.name, pendingDirectory)
                    currentCu = cu
                    includesByFile[rec.name] = IncludeContext(cu, this, sharedHeaderRegistry)
                    pendingDirectory = null
                    currentCuFinalised = true
                }

                StabType.N_SO -> {
                    currentCu = null
                    pendingDirectory = null
                    currentCuFinalised = false
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
                StabType.N_SO if (rec.name.endsWith('/')) -> {
                    pendingDirectory = rec.name
                    currentCuFinalised = false
                }

                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    if (currentCuFinalised) continue // cfront extra N_SO — ignore
                    currentCu = SourceFile.CUSource(rec.name, pendingDirectory)
                    pendingDirectory = null
                    currentCuFinalised = true
                    if (rec.value != 0L) {
                        log(
                            "file-start",
                            "${currentCu?.directory.orEmpty()}${rec.name} starts here",
                            Level.DEBUG,
                            address = resolver.buildAddress(rec.value),
                        )
                    }
                }

                StabType.N_SO -> {
                    if (rec.value != 0L) {
                        log(
                            "file-start",
                            "${currentCu?.filename} ends here",
                            Level.DEBUG,
                            address = resolver.buildAddress(rec.value),
                        )
                    }
                    finaliseGcc12FunctionSize()
                    currentCu = null
                    pendingDirectory = null
                    currentCuFinalised = false
                    currentSourceForLines = null
                }

                // line context
                StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

                // N_SOL switches the source filename for subsequent N_SLINE
                // records. Empty name = no-op (handled in the drop branch).
                StabType.N_SOL if rec.name.isNotEmpty() -> {
                    currentSourceForLines = rec.name
                }

                // N_SLINE: line-number entry. desc = line, value =
                // either function-relative offset (gcc/COFF for PE
                // binaries; dbx-historical) or already-absolute (gcc on
                // ELF, where the assembler resolves these to text-section
                // addresses). Disambiguate by comparing to the current
                // function's start: a value smaller than the function's
                // start address is by construction relative, otherwise
                // it's already absolute.
                StabType.N_SLINE -> {
                    val source = currentSourceForLines ?: currentCu?.filename ?: continue
                    val funcStart = currentFunction?.addr?.address
                    val abs = when {
                        funcStart != null && rec.value < funcStart.offset -> funcStart.add(rec.value)
                        else -> resolver.buildAddress(rec.value)
                    }
                    lineEntriesByFile.getOrPut(source) { mutableListOf() } +=
                        LineEntry(rec.desc, SerializableAddress(abs))
                }

                StabType.N_FUN -> if (rec.name.isEmpty()) {
                    // End-of-function marker: rec.value = function size relative to start.
                    currentFunction?.let { it.sizeBytes = rec.value }
                    currentFunction = null
                } else {
                    // gcc 12 ELF doesn't emit the empty-name N_FUN
                    // end marker — it relies on the outermost N_RBRAC
                    // instead. Before opening a new function, finalise
                    // the previous one from its scope brackets if its
                    // sizeBytes is still 0.
                    finaliseGcc12FunctionSize()
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
                                    decl = SymbolDecl.Function(decl.name, decl.isFileStatic, decl.type),
                                    cu = currentCu!!,
                                    locals = mutableListOf(),
                                    params = mutableListOf(),
                                    scopeBrackets = mutableListOf(),
                                    // A function lives in the CU it was
                                    // declared in, not in whichever header
                                    // it happens to inline from. N_SOL may
                                    // have switched to a header for prior
                                    // statements; prefer the CU filename.
                                    sourceFile = currentCu?.filename,
                                    startLine = rec.desc,
                                )
                                openFunctions += open
                                currentFunction = open
                            }

                            is SymbolDecl.StaticVar -> harvestSymbol(rec) { parseErrors++ }

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
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam ->
                                open.params += ParamRecord(decl, rec.value)

                            is SymbolDecl.RegLocal ->
                                open.locals.add(LocalRecord(decl, rec.value, i))

                            else -> log("unexpected-psym-rsym", "@$i: $decl")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    when (val decl = parseSymbol(rec)) {
                        is SymbolDecl.TaggedType -> {
                            // Outer typeAst + every InlineDef (`(0,N)=…`)
                            // bound inside the struct body. gcc heavily uses
                            // inline-bound ids for field types (anon pointers,
                            // arrays, function pointers) — without recursing
                            // through walkDefinitions those ids are referenced
                            // by `Ref(id)` from other types but never harvested
                            // as their own TypeAst, producing dangling refs
                            // and undefined field types downstream.
                            val outer = TypeAst(currentCu!!, decl.id, decl.name, decl.type)
                            appendAsts(outer, *walkDefinitions(decl.type).toTypedArray())
                        }

                        is SymbolDecl.Typedef -> {
                            // `name:t(cu,n)` with no `=body` parses as
                            // `Typedef(name, id, Ref(id))` — a self-Ref. The
                            // typedef adds a name but no new type definition,
                            // so emitting it as a TypeAst would create a
                            // body-less alias that collides with the real
                            // definition at the same id in another CU
                            // (every box2d typedef went this way).
                            if (decl.type !is TypeDecl.Ref || decl.type.id != decl.id) {
                                val outer = TypeAst(currentCu!!, decl.id, decl.name, decl.type)
                                appendAsts(outer, *walkDefinitions(decl.type).toTypedArray())
                            }
                        }

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                            currentFunction?.locals?.add(LocalRecord(decl, rec.value, i))
                        }

                        is SymbolDecl.StaticVar -> {
                            // Function-scope static variables get their actual address from rec.value
                            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } +=
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
                // otherwise drown the log under similar high-volume records).
                StabType.N_DSLINE, StabType.N_BSLINE, StabType.N_FLINE,
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

        synthesizeXRefStubsForDanglingInheritanceRefs()

        return Harvest(
            typeAsts = typeAsts,
            parseErrors = parseErrors,
            rawCollisions = collidingAsts,
            symbolsByCu = symbolsByCu,
            openFunctions = openFunctions,
            lineEntries = lineEntriesByFile.mapValues { (_, v) -> v.sortedBy { it.line } },
        )
    }

    /**
     * gcc 12 has a units bug emitting C++ inheritance as a leading
     * pseudo-field instead of the documented `!N,<bases>;` form. Verified
     * via objdump and via gdb itself:
     *
     *   $ rg 'XMLText:T' xmltest-record.json
     *   XMLText:T(0,81)=s112XMLNode:(0,25),0,6656;_isCData:(0,9),832,8;;
     *
     *   $ objdump -g xmltest
     *   struct XMLText {                 // size 112 id 3
     *     struct XMLNode XMLNode;        // bitsize 6656, bitpos 0
     *     enum { False, True } _isCData; // bitsize 8,    bitpos 832
     *   };
     *
     *   $ gdb> ptype XMLText
     *   internal-error: create_range_type: Assertion
     *     `index_type->length () > 0' failed.
     *
     * XMLNode is 104 bytes (832 bits). The emitted bitsize is 6656 = 832 × 8
     * = bytes × 64 — gcc applied the byte→bit conversion twice. binutils,
     * objdump, and gdb all read the bogus value as-is; the actual byte
     * layout survives because subsequent code uses `field_type->length()`,
     * not bitsize. gdb crashes elsewhere on the same data, so consider this
     * stab genuinely malformed.
     *
     * Detection: `field.sizeBits > struct.sizeBytes * 8`. A real field
     * cannot exceed its enclosing struct — that's the unambiguous signal.
     * The dangling id `(0,N)` referenced here is the base class; the field
     * name carries the base's source-level name (the convention is to use
     * the base class identifier verbatim). Synthesise an XRef-stub at the
     * dangling id named after the field, so [TypeResolver.lookupByXRef]
     * can cross-CU-resolve it to the real struct.
     */
    private fun synthesizeXRefStubsForDanglingInheritanceRefs() {
        val synthetic = mutableListOf<TypeAst>()
        // Per outer struct id: pseudo-fields detected as inheritance edges.
        // We rewrite the outer ast to move those fields into `bases` so the
        // materialiser's BaseInsertionPlanner / firstPolymorphicBase /
        // vtable wiring sees the inheritance.
        val outerRewrites =
            mutableMapOf<GlobalTypeId, MutableList<FieldDecl<GlobalTypeId>>>()
        for (ast in typeAsts.values) {
            val struct = ast.body as? TypeDecl.Struct ?: continue
            val structBits = struct.sizeBytes * 8
            for (field in struct.fields) {
                val ref = field.type as? TypeDecl.Ref ?: continue
                if (field.name.isEmpty()) continue
                if (field.sizeBits <= structBits) continue
                // Bases-rewrite fires for every detected pseudo-field, even
                // when the dangling Ref happens to be bound — gcc-12's bogus
                // bitsize signal is independent of cross-CU resolution.
                outerRewrites.getOrPut(ast.id) { mutableListOf() }.add(field)
                // XRef-stub synthesis is only needed when the dangling Ref
                // has no binding anywhere; otherwise the materialiser can
                // resolve `Ref(id)` directly.
                if (ref.id in typeAsts) continue
                synthetic.add(
                    TypeAst(
                        cu = ast.cu,
                        id = ref.id,
                        name = field.name,
                        body = TypeDecl.XRef(AggrKind.STRUCT, field.name),
                    ),
                )
            }
        }
        if (synthetic.isNotEmpty()) {
            log(
                "xref-stubs-synthesized",
                "${synthetic.size} inheritance-pseudo-field Refs → synthetic XRef stubs",
            )
            appendAsts(*synthetic.toTypedArray())
        }
        for ((outerId, pseudoFields) in outerRewrites) {
            val outer = typeAsts[outerId] ?: continue
            val struct = outer.body as? TypeDecl.Struct ?: continue
            val pseudoSet = pseudoFields.toSet()
            val newBases = struct.bases + pseudoFields.map { f ->
                BaseDecl(
                    type = f.type,
                    isVirtual = false,
                    access = Access.PUBLIC,
                    offsetBits = f.offsetBits,
                )
            }
            val newFields = struct.fields.filter { it !in pseudoSet }
            typeAsts[outerId] = outer.copy(
                body = struct.copy(bases = newBases, fields = newFields),
            )
        }
        if (outerRewrites.isNotEmpty()) {
            log(
                "inheritance-pseudo-fields-promoted",
                "${outerRewrites.size} outer struct(s) rewritten to populate bases[]",
            )
        }
    }

    private fun harvestSymbol(rec: StabRecord, onError: () -> Unit) {
        try {
            val decl = parseSymbol(rec)
            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += HarvestedSymbol(
                decl,
                rec.type,
                rec.value,
            )
        } catch (e: StabsParseException) {
            onError()
            log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }

    fun walkDefinitions(decl: TypeDecl<GlobalTypeId>): List<TypeAst> = when (decl) {
        is TypeDecl.Builtin, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.Enum, is TypeDecl.Range,
        is TypeDecl.Ref, is TypeDecl.XRef,
        -> listOf()

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

        // Emit the outer InlineDef's TypeAst AND recurse into its body —
        // gcc nests InlineDefs (e.g. an outer Method whose return type is
        // itself an inline-defined Pointer-to-X), and without the
        // recursion the inner ids are referenced by other types but
        // never registered. Result: the contentHash oracle can't resolve
        // the Refs, per-CU clones diverge, and the appendAsts collision
        // log surfaces hundreds of false "different hash" entries.
        is TypeDecl.InlineDef -> listOf(TypeAst(currentCu!!, decl.id, null, decl.body)) +
            walkDefinitions(decl.body)
    }

    /**
     * Accumulate [TypeAst]s into [typeAsts] with first-writer-wins on
     * GlobalTypeId collisions.
     *
     * 1. **Non-colliding:** insert as-is.
     * 2. **Existing XRef placeholder:** replaced by any concrete body that
     *    arrives later for the same id (see filter on the collision set).
     * 3. **GlobalTypeId already taken:** record every alternate body into
     *    [collidingAsts] for post-harvest classification, then drop the
     *    new entries. No per-collision logging or `contentHash` walk
     *    here — that turned the harvest into a 10-minute affair on
     *    template-heavy binaries. `Harvest.classifyCollisions` runs once
     *    after harvest against a fully populated `typeAsts` and the
     *    memoized `hashCache` to surface real-vs-spurious counts; see
     *    `StabsImporter`.
     */
    fun appendAsts(vararg asts: TypeAst) {
        val new = asts.groupBy { it.id }
        val collisions = new.keys.intersect(typeAsts.keys).filter { typeAsts[it]?.body !is TypeDecl.XRef }
        for (id in collisions) {
            val ex = typeAsts[id]!!
            val incoming = new[id]!!

            // Name-promotion: an anonymous InlineDef-extracted TypeAst can be
            // superseded by an explicit named Typedef for the same id (same CU-local
            // type). The `of` self-ref in Range bodies differs between the two
            // forms, so we don't require body equality — just that both are
            // non-XRefTarget (primitive-like) and the existing is unnamed.
            val namedIncoming = incoming.firstOrNull { it.name != null && !it.body.isXRefTarget }
            if (namedIncoming != null && ex.name == null && !ex.body.isXRefTarget) {
                typeAsts[id] = namedIncoming
                continue
            }

            // Cheap-equality skip: if every alternate body is `==` to
            // the merged entry (data-class structural equality, no
            // Ref-walk), the collision is a literal re-emission and
            // not worth recording. classifyCollisions does the deeper
            // Ref-aware check later for the entries that survive.
            val alternates = incoming.filter { it.body != ex.body }.map { it.body }
            if (alternates.isEmpty()) continue
            val bucket = collidingAsts
                .getOrPut(id) { mutableMapOf() }
                .getOrPut(ex.nameOrId) { mutableSetOf() }
            bucket.add(ex.body)
            bucket.addAll(alternates)
        }

        for (ast in asts.filter { !collisions.contains(it.id) }) {
            typeAsts[ast.id] = ast
        }
    }

    fun parseSymbol(rec: StabRecord) = Parser(rec.name).parseSymbol().globalize(this).also {
        appendAsts(*walkDefinitions(it.type).toTypedArray())
    }
}
