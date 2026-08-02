package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.importer.AddressResolver
import ghistabs.parse.*

/**
 * Position in the stab record stream — the state a flat stream of records only means anything
 * against: which CU/include/source file is open, which function is open, and what has accumulated
 * while advancing (line entries, functions). Owning position and accumulation together is what lets
 * an N_SLINE resolve its function-relative address and file itself under both the source file and
 * the open function; [ghistabs.parse.Cursor] is the same idea one level down, within a single stab.
 *
 * Also the [Globalizer] — a [LocalTypeId]'s file number only means something against the
 * [IncludeContext] of the CU that emitted it. The [HeaderRegistry] is shared across those contexts
 * so two CUs that BINCL the same (filename, checksum) get identical GlobalTypeIds for
 * header-attributed types (stabs-canonicalization.md §3).
 */
class StabCursor(private val resolver: AddressResolver, sink: DiagnosticSink) :
    DiagnosticSink by sink,
    Globalizer {

    private val includesByFile = mutableMapOf<String, IncludeContext>()
    private val sharedHeaderRegistry = HeaderRegistry(this)
    private val lineEntriesByFile = mutableMapOf<String, MutableList<LineEntry>>()

    /**
     * Pending compilation directory from a trailing-slash N_SO (stabs.texinfo §"Source
     * Files": gcc emits dir-N_SO then filename-N_SO back-to-back; we pair them).
     */
    private var pendingDirectory: String? = null

    /**
     * Active filename for N_SLINE attribution. N_SOL switches it; N_SO end-of-CU clears.
     * Without this, lines inside #include'd headers would file under the enclosing CU.
     */
    private var currentSourceForLines: String? = null

    var currentCu: SourceFile.CUSource? = null
        private set

    /**
     * A function being accumulated: its record-order params and its block tree, held beside it
     * rather than on it. Not a map keyed by [OpenFunction] — that is a data class whose hashCode
     * moves as its lineEntries and sizeBytes fill in.
     */
    private class OpenScope(val function: OpenFunction) {
        val blocks = BlockTreeBuilder()
        val params = mutableListOf<SymbolRecord>()
    }

    private val scopes = mutableListOf<OpenScope>()
    private var currentScope: OpenScope? = null

    val currentFunction get() = currentScope?.function

    /** [currentCu] where a record can't legally appear outside a CU. */
    val cu get() = checkNotNull(currentCu) { "record outside any N_SO" }

    val lineSource get() = currentSourceForLines ?: currentCu?.filename

    private val currentInclude get() = includesByFile[currentCu?.filename]

    override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceFor(id) ?: cu, id.n)

    /**
     * Build every CU's [IncludeContext] up front, so an N_BINCL file number is resolvable from the
     * first record of the CU that uses it rather than only once the stream reaches the BINCL.
     */
    fun preSeedHeaders(records: List<StabRecord>) {
        for (rec in records) {
            when (rec.type) {
                StabType.N_SO if rec.name.endsWith('/') -> pendingDirectory = rec.name

                StabType.N_SO if rec.name.isNotEmpty() -> {
                    currentCu = SourceFile.CUSource(rec.name, pendingDirectory)
                    includesByFile[rec.name] = IncludeContext(cu, this, sharedHeaderRegistry)
                    pendingDirectory = null
                }

                StabType.N_SO -> {
                    currentCu = null
                    pendingDirectory = null
                }

                StabType.N_BINCL -> currentInclude?.beginInclude(rec.name, rec.value)
                StabType.N_EINCL -> currentInclude?.endInclude()
                StabType.N_EXCL -> currentInclude?.remount(rec.name, rec.value)
                else -> {}
            }
        }
    }

    /** N_SO: trailing slash = compilation directory, non-empty = CU start, empty = CU end. */
    fun sourceUnit(rec: StabRecord) {
        when {
            rec.name.endsWith('/') -> pendingDirectory = rec.name

            rec.name.isNotEmpty() -> {
                finaliseGcc12FunctionSize()
                currentCu = SourceFile.CUSource(rec.name, pendingDirectory)
                pendingDirectory = null
                if (rec.value != 0L) {
                    debug(
                        "file-start",
                        "${currentCu?.directory.orEmpty()}${rec.name} starts here",
                        address = resolver.buildAddress(rec.value),
                    )
                }
            }

            else -> {
                if (rec.value != 0L) {
                    debug(
                        "file-start",
                        "${currentCu?.filename} ends here",
                        address = resolver.buildAddress(rec.value),
                    )
                }
                finaliseGcc12FunctionSize()
                currentCu = null
                pendingDirectory = null
                currentSourceForLines = null
            }
        }
    }

    /** N_SOL: switch the file N_SLINEs are attributed to, without leaving the CU. */
    fun switchSource(name: String) {
        currentSourceForLines = name
    }

    /**
     * N_SLINE: `desc` is the line, `value` is function-relative (gcc/COFF on PE) or already
     * absolute (gcc/ELF) — [AddressResolver.stabAddress] disambiguates against the function start.
     */
    fun lineEntry(rec: StabRecord) {
        val source = lineSource ?: return
        val entry = LineEntry(rec.desc, resolver.stabAddress(rec.value, currentFunction?.addr), source)
        lineEntriesByFile.getOrPut(source) { mutableListOf() } += entry
        currentFunction?.lineEntries?.add(entry)
    }

    /** Named N_FUN: `name` is `mangled:descriptor`, `value` the entry address. */
    fun openFunction(rec: StabRecord, decl: SymbolDecl.Function<GlobalTypeId>) {
        finaliseGcc12FunctionSize()
        val function = OpenFunction(rec.name.substringBefore(':'), resolver.buildAddress(rec.value), decl, cu)
        currentScope = OpenScope(function).also { scopes += it }
    }

    /** N_PSYM / register-param N_RSYM: the function's own, so no block resolution needed. */
    fun param(record: SymbolRecord) {
        currentScope?.params?.add(record)
    }

    /** N_LSYM / N_RSYM local: held by the block builder until a bracket claims it. */
    fun local(record: SymbolRecord) {
        currentScope?.blocks?.local(record)
    }

    /** Empty-name N_FUN end marker: `value` is the size relative to the function start. */
    fun closeFunction(rec: StabRecord) {
        currentFunction?.sizeBytes = rec.value.toULong()
        currentScope = null
    }

    /** N_LBRAC: open a lexical scope, which owns the locals emitted just before it. */
    fun openScope(rec: StabRecord) {
        currentScope?.let { it.blocks.open(resolver.stabAddress(rec.value, it.function.addr)) }
    }

    /** N_RBRAC: close the innermost lexical scope. */
    fun closeScope(rec: StabRecord) {
        currentScope?.let { it.blocks.close(resolver.stabAddress(rec.value, it.function.addr)) }
    }

    /**
     * gcc 12 (and modern ELF emitters) omit the empty-name N_FUN end marker, delimiting
     * with the outermost N_RBRAC instead. Compute size from brackets before swapping
     * function context.
     */
    private fun finaliseGcc12FunctionSize() {
        val scope = currentScope ?: return
        val f = scope.function
        if (f.sizeBytes != null) return
        val lastClose = scope.blocks.lastClose ?: return
        f.sizeBytes = (lastClose.offset - f.addr.offset).toULong()
    }

    /** Functions with their block trees resolved, and line entries grouped by source and sorted. */
    fun toHarvest(): Pair<List<OpenFunction>, Map<String, List<LineEntry>>> {
        for (scope in scopes) {
            val f = scope.function
            // The function's own file: its lowest-address line entry, matching TypeResolver.functionSource.
            val source = f.lineEntries.minByOrNull { it.addr.offset }?.source ?: f.cu.filename
            val (blocks, locals) = scope.blocks.finish(f.lineEntries, source)
            f.blocks = blocks
            f.locals = locals
            f.params = scope.params.map { it.copy(sourceFile = source) }
        }
        return scopes.map { it.function } to
            lineEntriesByFile.mapValues { (_, v) -> v.sortedWith(compareBy({ it.line }, { it.addr.offset })) }
    }
}
