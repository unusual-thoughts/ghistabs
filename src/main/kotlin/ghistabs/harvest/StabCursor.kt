package ghistabs.harvest

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghistabs.diagnose.DiagnosticSink
import ghistabs.importer.AddressResolver
import ghistabs.minus
import ghistabs.parse.*
import ghistabs.rangeTo
import java.util.*

/**
 * Position in the stab record stream — the state a flat stream of records only means anything
 * against: which CU/include/source file is open, which function is open, and what has accumulated
 * while advancing (line entries, functions). Owning position and accumulation together is what lets
 * an N_SLINE resolve its function-relative address and file itself under both the source file and
 * the open function; [ghistabs.parse.Cursor] is the same idea one level down, within a single stab.
 *
 * Also, the [Globalizer] — a [LocalTypeId]'s file number only means something against the
 * [IncludeContext] of the CU that emitted it. The [HeaderRegistry] is shared across those contexts
 * so two CUs that BINCL the same (filename, checksum) get identical GlobalTypeIds for
 * header-attributed types (stabs-canonicalization.md §3).
 */
class StabCursor(private val resolver: AddressResolver, sink: DiagnosticSink) :
    DiagnosticSink by sink,
    Globalizer {

    private val includesByFile = mutableMapOf<SourceFile.CUSource, IncludeContext>()
    private val sharedHeaderRegistry = HeaderRegistry(this)
    private val lineEntriesByFile = mutableMapOf<GhidraSourceFile, MutableList<LineEntry>>()

    // (address, file) where gcc said the text switches; null file = the CU's text ended there.
    private val textBoundaries = mutableListOf<Pair<Address, GhidraSourceFile?>>()

    // [N_SO start, N_SO end] per CU — which CU owns each run of text, one level above the file
    // partition. The gaps between them are the shared COMDAT region.
    private val cuRanges = mutableMapOf<AddressRange, GhidraSourceFile>()

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

    private var currentCu: SourceFile.CUSource? = null

    /**
     * A function being accumulated: its record-order params and its block tree
     */
    private inner class FunctionScope(func: FunctionSymbol, val cu: SourceFile.CUSource) {
        val blocks = BlockTreeBuilder()
        val params = mutableListOf<ParamSymbol>()
        val lineEntries = mutableListOf<LineEntry>()
        var sizeBytes: ULong? = null
        val decl = func.body
        val name = func.body.name.substringBefore(':')
        val addr = resolver.forSymbol(func)!!
        val declLine = func.line

        fun toHarvested(): Func {
            // The function's own file: its lowest-address line entry, matching TypeResolver.functionSource.
            // Not the N_SO/N_SOL partition at the entry — measured at 1155 overrides on locale_test,
            // and wrong where it fires (`std::_Destroy` reads stl_construct.h by its lines and
            // `iomanip` by the partition, the label having been planted mid-symbol-flush).
            val source = lineEntries.minByOrNull { it.addr.offset }?.source ?: cu.identity
            // gcc 12 and modern ELF emitters omit the empty-name N_FUN end marker and delimit with
            // the outermost N_RBRAC instead. Read here rather than at every context switch: no
            // bracket can join a function once the next one opens.
            val extent = sizeBytes ?: blocks.lastClose?.let { (it.offset - addr.offset).toULong() }
            val (locals, attributedBlocks) = blocks.finish(lineEntries, source)
            val attributedParams = params.map { it.copy(sourceFile = source) }
            return Func(
                name, addr, decl, cu, locals, attributedParams, attributedBlocks, lineEntries, extent, declLine,
            )
        }
    }

    private val scopes = mutableListOf<FunctionScope>()
    private var currentScope: FunctionScope? = null

    /** [currentCu] where a record can't legally appear outside a CU. */
    val cu get() = checkNotNull(currentCu) { "record outside any N_SO" }

    private val lineSource get() = sourceFileOrNull(currentSourceForLines) ?: cu.identity

    private val currentFunctionName get() = currentScope?.name

    private val currentInclude get() = includesByFile[currentCu]

    override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceFor(id) ?: cu, id.n)

    fun parseSymbol(rec: StabRecord) = Symbol.parse(rec, this, lineSource, currentFunctionName)

    /**
     * Build every CU's [IncludeContext] up front, so an N_BINCL file number is resolvable from the
     * first record of the CU that uses it rather than only once the stream reaches the BINCL.
     */
    fun preSeedHeaders(records: Iterable<StabRecord>) {
        for (rec in records) {
            when (rec.type) {
                StabType.N_SO if rec.name.endsWith('/') -> pendingDirectory = rec.name

                StabType.N_SO if rec.name.isNotEmpty() -> {
                    currentCu = SourceFile.CUSource(rec.name, pendingDirectory).also {
                        includesByFile[it] = IncludeContext(it, rec.boundaryAddress, this, sharedHeaderRegistry)
                    }
                    pendingDirectory = null
                }

                StabType.N_SO -> {
                    currentCu = null
                    pendingDirectory = null
                }

                StabType.N_BINCL -> currentInclude?.beginInclude(resolved(rec.name), rec.value)

                StabType.N_EINCL -> currentInclude?.endInclude()

                StabType.N_EXCL -> currentInclude?.remount(resolved(rec.name), rec.value)

                else -> {}
            }
        }
    }

    /** N_SO: trailing slash = compilation directory, non-empty = CU start, empty = CU end. */
    fun sourceUnit(rec: StabRecord) {
        when {
            rec.name.endsWith('/') -> pendingDirectory = rec.name

            rec.name.isNotEmpty() -> {
                currentCu = SourceFile.CUSource(rec.name, pendingDirectory)
                pendingDirectory = null
                rec.boundary(cu.identity)
            }

            else -> {
                // The N_SO value ends the CU's text. What follows until the next CU is COMDAT and
                // template instantiation shared between CUs and owned by none, so nothing opens here.
                rec.boundary(null)
                span(currentInclude?.start, rec.boundaryAddress)?.to(cu.identity)?.let { cuRanges += it }
                currentCu = null
                pendingDirectory = null
                currentSourceForLines = null
            }
        }
    }

    /** N_SOL: switch the file N_SLINEs are attributed to, without leaving the CU. */
    fun switchSource(rec: StabRecord) {
        currentSourceForLines = resolved(rec.name)
        rec.boundary(lineSource)
    }

    /**
     * An N_SO/N_SOL address boundary: `value` is where the named file's text starts and the previous
     * file's ends (stabs.texinfo §"Source Files"), so the two records partition the text between them.
     * A null [source] closes the run without opening one.
     *
     * Carries no line — gcc hardcodes `desc` to 0 for both (`dbxout_source_file`) — so this is kept
     * apart from [lineEntry]: a zero line reaching [ghistabs.render.FunctionSpans] reads as a function opener.
     */
    private fun StabRecord.boundary(source: GhidraSourceFile?) {
        val addr = boundaryAddress ?: return
        textBoundaries += addr to source
        // Two categories, because an addressed diagnostic is a Ghidra bookmark filed under
        // `Stabs:<category>`: browsing where a CU begins and ends is a different question from
        // browsing where an include took over mid-CU.
        when {
            type == StabType.N_SOL -> debug("linesource-start", "source switches to $source", address = addr)
            source != null -> debug("file-start", "$source starts here", address = addr)
            else -> debug("file-start", "${currentCu?.filename} ends here", address = addr)
        }
    }

    // Absolute, never function-relative: gcc values both records with an `Ltext<n>` label
    // ([dbxout_init], [dbxout_source_file], and dbxcoff.h's trailing `Letext`), and on COFF only
    // line numbers and block addresses are function-relative. Passing the open function's start
    // rewrote the 178 bouniaf boundaries that legitimately sit below it.
    private val StabRecord.boundaryAddress get() = value.takeIf { it != 0L }
        ?.let { resolver.stabAddress(it, funcStart = null, sink = this@StabCursor) }

    /** A `../`-relative spelling anchored to this CU's compilation directory. */
    private fun resolved(name: String) = resolveAgainstDirectory(name, currentCu?.directory)

    /**
     * N_SLINE: `desc` is the line, `value` is function-relative (gcc/COFF on PE) or already
     * absolute (gcc/ELF) — [AddressResolver.stabAddress] disambiguates against the function start.
     */
    fun lineEntry(rec: StabRecord) =
        LineEntry(rec.desc, resolver.stabAddress(rec.value, currentScope?.addr, this), lineSource).also {
            lineEntriesByFile.getOrPut(lineSource) { mutableListOf() } += it
            currentScope?.lineEntries?.add(it)
        }

    /** Named N_FUN: `name` is `mangled:descriptor`, `value` entry address, `desc` declaration line (under -gstabs+) */
    fun openFunction(func: FunctionSymbol) {
        currentScope = FunctionScope(func, cu).also { scopes += it }
    }

    /** N_PSYM / register-param N_RSYM: the function's own, so no block resolution needed. */
    fun param(record: ParamSymbol) {
        currentScope?.params?.add(record)
    }

    /** N_LSYM / N_RSYM local: held by the block builder until a bracket claims it. */
    fun local(record: LocalSymbol) {
        currentScope?.blocks?.local(record)
    }

    /** Empty-name N_FUN end marker: `value` is the size relative to the function start. */
    fun closeFunction(rec: StabRecord) {
        currentScope?.sizeBytes = rec.value.toULong()
        currentScope = null
    }

    fun bracket(rec: StabRecord) {
        currentScope?.apply {
            val addr = resolver.stabAddress(rec.value, addr, this@StabCursor)
            when (rec.type) {
                // open a lexical scope, which owns the locals emitted just before it.
                StabType.N_LBRAC -> blocks.open(addr)

                // close the innermost lexical scope.
                StabType.N_RBRAC -> blocks.close(addr)

                else -> {}
            }
        }
    }

    /** Functions with their block trees resolved, and line entries grouped by source and sorted. */
    fun toHarvest() = HarvestedStream(
        scopes.map { it.toHarvested() }.withBoundedExtents(cuRanges),
        lineEntriesByFile.mapValues { (_, v) -> v.sortedWith(compareBy({ it.line }, { it.addr.offset })) },
        textRanges = textPartition(),
        cuRanges,
    )

    /**
     * The boundaries folded into disjoint ranges: each file's run of text ends where the next
     * boundary begins, and the last one at the end of the memory block holding it — the program is
     * the only thing that knows where the text stops once the stabs have stopped partitioning it.
     */
    private fun textPartition(): Map<AddressRange, GhidraSourceFile> {
        val distinct = textBoundaries.distinct()
        val sorted = distinct.sortedBy { it.first }
        if (sorted != distinct) debug("text-boundaries-out-of-order")
        // Where each run ends: at the next boundary, and for the last at the end of the memory block
        // holding it. A block Ghidra cannot name leaves that list one short, and `zip` truncating to
        // it is what drops the unterminated run.
        val ends = sorted.drop(1).map { it.first } +
            listOfNotNull(sorted.lastOrNull()?.let { resolver.blockEnd(it.first)?.next() })
        return sorted.zip(ends) { (start, source), end ->
            source?.let { span(start, end)?.to(it) }
        }.filterNotNull().toMap()
    }

    /**
     * Functions gcc gave no extent — no end-marker N_FUN, no brackets — bounded by whatever does say
     * where they stop: the next entry point, or the end of the CU's own text, whichever comes first.
     */
    private fun List<Func>.withBoundedExtents(cus: Map<AddressRange, GhidraSourceFile>) =
        mapTo(TreeSet()) { it.addr }.let { starts ->
            map { func ->
                when (func.sizeBytes) {
                    null -> {
                        val cuEnd = cus.keys.firstOrNull { it.contains(func.addr) }?.maxAddress?.next()
                        listOfNotNull(starts.higher(func.addr), cuEnd).minOrNull()?.let {
                            val which = if (it == cuEnd) "cu-end" else "next-entry"
                            debug("function-extent-from-$which", func.name, address = func.addr)
                            func.copy(sizeBytes = (it - func.addr).toULong())
                        } ?: func
                    }

                    else -> func
                }
            }
        }
}

/** What one pass over the stream accumulated, beyond the type store. */
data class HarvestedStream(
    val functions: List<Func>,
    val lineEntries: Map<GhidraSourceFile, List<LineEntry>>,
    val textRanges: Map<AddressRange, GhidraSourceFile>,
    val cuRanges: Map<AddressRange, GhidraSourceFile>,
)

/**
 * The range between two boundaries, or null where there is none to make: an address missing, or the
 * two landing together — an N_SO and the N_SOL after it share one address, and a CU can bracket no
 * text at all. Ghidra's ends are inclusive, so the exclusive [end] loses one on the way in.
 */
private fun span(start: Address?, end: Address?) =
    if (start != null && end != null && end > start) start..(end - 1) else null
