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

    var currentFunction: OpenFunction? = null
        private set

    private val openFunctions = mutableListOf<OpenFunction>()

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
        currentFunction = OpenFunction(rec.name.substringBefore(':'), resolver.buildAddress(rec.value), decl, cu)
            .also { openFunctions += it }
    }

    /** Empty-name N_FUN end marker: `value` is the size relative to the function start. */
    fun closeFunction(rec: StabRecord) {
        currentFunction?.sizeBytes = rec.value.toULong()
        currentFunction = null
    }

    fun bracket(rec: StabRecord, index: Int) {
        currentFunction?.let { it.scopeBrackets += Bracket(rec.type, resolver.stabAddress(rec.value, it.addr), index) }
    }

    /**
     * gcc 12 (and modern ELF emitters) omit the empty-name N_FUN end marker, delimiting
     * with the outermost N_RBRAC instead. Compute size from brackets before swapping
     * function context.
     */
    private fun finaliseGcc12FunctionSize() {
        val f = currentFunction ?: return
        if (f.sizeBytes != null) return
        val lastRbrac = f.scopeBrackets.filter { it.type == StabType.N_RBRAC }.maxOfOrNull { it.addr.offset } ?: return
        f.sizeBytes = (lastRbrac - f.addr.offset).toULong()
    }

    /** Functions with their block trees resolved, and line entries grouped by source and sorted. */
    fun toHarvest(): Pair<List<OpenFunction>, Map<String, List<LineEntry>>> {
        openFunctions.forEach { it.resolveBlocks() }
        return openFunctions to
            lineEntriesByFile.mapValues { (_, v) -> v.sortedWith(compareBy({ it.line }, { it.addr.offset })) }
    }
}
