package ghistabs.harvest

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghistabs.diagnose.DiagnosticSink
import ghistabs.parse.*
import ghistabs.rangeUntil

/**
 * Position in the stab record stream — the state a flat stream of records only means anything
 * against: which CU/include/source file is open, which function is open, and what has accumulated
 * while advancing (line entries, functions). Owning position and accumulation together is what lets
 * an N_SLINE resolve its function-relative address and file itself under both the source file and
 * the open function; [ghistabs.parse.Cursor] is the same idea one level down, within a single stab.
 *
 * Also, the [Globalizer] — a [LocalTypeId]'s file number only means something against the
 * [CuContext] of the CU that emitted it. The [HeaderRegistry] is shared across those contexts
 * so two CUs that BINCL the same (filename, checksum) get identical GlobalTypeIds for
 * header-attributed types (stabs-canonicalization.md §3).
 */
class StabCursor(private val resolver: AddressResolver, sink: DiagnosticSink) :
    DiagnosticSink by sink,
    Globalizer {

    /**
     * One per named N_SO, in stream order: two CUs can share a [SourceFile.CUSource] (libgcc2.c, once
     * per `L_` object).
     */
    private val cuContexts = mutableListOf<CuContext>()

    /** The open CU's context. [preSeedHeaders] appends them, the second pass steps through them by [cusOpened]. */
    private var cuContext: CuContext? = null
    private var cusOpened = 0
    private val sharedHeaderRegistry = HeaderRegistry(this)
    private val lineEntriesByFile = mutableMapOf<GhidraSourceFile, MutableList<LineEntry>>()

    // (address, file) where gcc said the text switches; null file = the CU's text ended there.
    private val textBoundaries = mutableListOf<Pair<Address, GhidraSourceFile?>>()

    /**
     * Pending compilation directory from a trailing-slash N_SO (stabs.texinfo §"Source
     * Files": gcc emits dir-N_SO then filename-N_SO back-to-back; we pair them).
     */
    private var pendingDirectory: String? = null

    /**
     * Active filename for N_SLINE attribution. N_SOL switches it; any N_SO opening or ending a CU
     * clears it. gcc 2.6.3 a.out has no end-of-CU N_SO, so the next CU's start is the only reset.
     * Without this, lines inside #include'd headers would file under the enclosing CU.
     */
    private var currentSourceForLines: String? = null

    private val currentCu get() = cuContext?.cu

    private var currentScope: FuncBuilder? = null

    /** [currentCu] where a record can't legally appear outside a CU. */
    private val cu get() = checkNotNull(currentCu) { "record outside any N_SO" }

    private val lineSource get() = sourceFileOrNull(currentSourceForLines) ?: cu.identity

    private val currentFunctionName get() = currentScope?.func?.name

    override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(cuContext?.sourceFor(id) ?: cu, id.n)

    /** Null for an unparseable symbol, and for one outside any CU — whose type ids have no file to resolve in. */
    fun parseSymbol(rec: StabRecord) = when (val res = currentCu?.let { Parser(rec.name).parseSymbol() }) {
        null -> null.also { outsideCu(rec) }

        is ParseResult.Error -> {
            err("parse-error", "@${rec.index} '${rec.name.take(80)}': ${res.ex.message}")
            null
        }

        is ParseResult.Ok -> {
            res.trailing?.let { warn("unparsed-trailing", it) }
            res.skipped.forEach { warn("unparsed-skipped", "@${rec.index} '${rec.name.take(80)}': $it") }
            Symbol(rec, res.inner.globalize(this), cu, lineSource, currentFunctionName)
        }
    }

    /**
     * Build every CU's [CuContext] up front, so an N_BINCL file number is resolvable from the
     * first record of the CU that uses it rather than only once the stream reaches the BINCL.
     */
    fun preSeedHeaders(records: Iterable<StabRecord>) {
        for (rec in records) {
            when (rec.type) {
                StabType.N_SO if rec.name.isDirectory -> pendingDirectory = rec.name

                StabType.N_SO if rec.name.isNotEmpty() -> {
                    val cu = SourceFile.CUSource(rec.name, pendingDirectory)
                    cuContext = CuContext(cu, this, sharedHeaderRegistry, rec.language, rec.boundaryAddress)
                        .also { cuContexts += it }
                    pendingDirectory = null
                }

                StabType.N_SO -> {
                    cuContext?.endAt(rec.boundaryAddress)
                    cuContext = null
                    pendingDirectory = null
                }

                StabType.N_BINCL -> cuContext?.beginInclude(resolved(rec.name), rec.value)

                StabType.N_EINCL -> cuContext?.endInclude()

                StabType.N_EXCL -> cuContext?.remount(resolved(rec.name), rec.value)

                else -> {}
            }
        }
    }

    fun rawSymbols(records: Iterable<StabRecord>) = buildList {
        for (record in records) {
            when (record.type) {
                StabType.N_UNDF, StabType.N_BINCL, StabType.N_EXCL, StabType.N_OPT -> {}

                StabType.N_SO -> sourceUnit(record)

                StabType.N_SOL -> switchSource(record)

                StabType.N_FUN if record.name.isEmpty() -> closeFunction(record)

                StabType.N_FUN -> parseSymbol(record)?.also {
                    if (it.body is SymbolDecl.Function) openFunction(it.retype(it.body))
                    add(it)
                }

                else -> if (record.name.isNotEmpty()) parseSymbol(record)?.let { add(it) }
            }
        }
    }

    /**
     * A record that needs a CU arriving outside every `N_SO` — a stream that never opens one, or
     * strays past its end. Skipped rather than filed under some other CU's name.
     */
    private fun outsideCu(rec: StabRecord) =
        warn("record-outside-cu", "@${rec.index} ${rec.type} '${rec.name.take(80)}' outside any N_SO; skipped")

    /** N_SO: trailing slash = compilation directory, non-empty = CU start, empty = CU end. */
    fun sourceUnit(rec: StabRecord) {
        when {
            // Paired with its filename N_SO in [preSeedHeaders], into the context's CUSource.
            rec.name.isDirectory -> {}

            rec.name.isNotEmpty() -> {
                cuContext = cuContexts[cusOpened++]
                currentSourceForLines = null
                rec.boundary(cu.identity)
            }

            else -> {
                // dbxcoff.h's `Letext`: the end of this object's plain .text. What follows is not the
                // COMDAT region — CU spans abut, 53 bytes of alignment apart on one PE fixture (§39).
                rec.boundary(null)
                cuContext = null
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

    // Not always absolute: `dbxout_source_file` skips its `text_section()` call when the open
    // function has a section of its own, planting `Ltext<n>` inside that section instead — 178 such
    // boundaries on one PE fixture, each an offset within its own function's body.
    private val StabRecord.boundaryAddress get() = value.takeIf { it != 0L }
        ?.let { resolver.stabAddress(it, currentScope?.func?.addr, sink = this@StabCursor) }

    private val StabRecord.language get() = Language.fromCode(desc)

    /** A `../`-relative spelling anchored to this CU's compilation directory. */
    private fun resolved(name: String) = name.resolveAgainstDirectory(currentCu?.directory)

    /**
     * N_SLINE: `desc` is the line, `value` is function-relative (gcc/COFF on PE) or already
     * absolute (gcc/ELF) — [AddressResolver.stabAddress] disambiguates against the function start.
     */
    fun lineEntry(rec: StabRecord) = cuContext?.let { context ->
        if (context.linesAhead == null && context.functions.isEmpty()) context.linesAhead = mutableListOf()
        // Ahead of its function, a value can't be relative to it.
        val scope = currentScope.takeIf { context.linesAhead == null }
        LineEntry(rec.desc, resolver.stabAddress(rec.value, scope?.func?.addr, this), lineSource).also {
            lineEntriesByFile.getOrPut(lineSource) { mutableListOf() } += it
            (context.linesAhead ?: scope?.lines)?.add(it)
        }
    } ?: null.also { outsideCu(rec) }

    /** Named N_FUN: `name` is `mangled:descriptor`, `value` entry address, `desc` declaration line (under -gstabs+) */
    fun openFunction(func: FunctionSymbol) {
        val context = checkNotNull(cuContext) { "N_FUN outside any N_SO" }
        currentScope = FuncBuilder(Func(func.body.name, resolver.forSymbol(func)!!, func.body, func.origin), this)
            .also { context.functions += it }
        context.linesAhead?.let {
            currentScope?.lines?.addAll(it)
            it.clear()
        }
    }

    /** N_PSYM / register-param N_RSYM: the function's own, so no block resolution needed. */
    fun param(record: ParamSymbol) {
        currentScope?.params?.add(record)
    }

    /** N_LSYM / N_RSYM local: held by the block builder until a bracket claims it. */
    fun local(record: LocalSymbol) {
        currentScope?.blockBuilder?.local(record)
    }

    /** Empty-name N_FUN end marker: `value` is the size relative to the function start. */
    fun closeFunction(rec: StabRecord) {
        currentScope?.sizeBytes = rec.value.toULong()
        currentScope = null
    }

    fun bracket(rec: StabRecord) {
        currentScope?.apply {
            val addr = resolver.stabAddress(rec.value, func.addr, this@StabCursor)
            val level = rec.desc.takeIf { it > 0 }
            when (rec.type) {
                // open a lexical scope, which owns the locals emitted just before it.
                StabType.N_LBRAC -> blockBuilder.open(addr, level)

                // close the innermost lexical scope.
                StabType.N_RBRAC -> blockBuilder.close(addr, level)

                else -> {}
            }
        }
    }

    /**
     * Line entries grouped by source and sorted, and — separately, because only a translation unit
     * has them — each CU's functions with their block trees resolved, its span and its language.
     *
     * The two are kept apart rather than joined here: an N_SOL-only header has line entries and no CU,
     * and a CU whose text all went to COMDAT has a span and no lines (59 of 61 on locale_test, §39).
     * Grouped rather than `mapKeys`'d because two CUSources can share one [SourceFile.identity], and
     * `mapKeys` would silently keep the last of them.
     */
    fun toHarvest(): HarvestedStream {
        val contexts = cuContexts.groupBy { it.cu.identity }
        // Eager, not `firstNotNullOfOrNull`: `addressRange()` files the verdict that explains a null
        // one, and short-circuiting would leave every context after the first unexplained.
        val spans = contexts.mapValues { (_, cs) -> cs.mapNotNull { it.addressRange() }.firstOrNull() }
        return HarvestedStream(
            lineEntries = lineEntriesByFile.mapValues { (_, es) ->
                es.sortedWith(compareBy({ it.line }, { it.addr.offset }))
            },
            cus = contexts.mapValues { (file, cs) ->
                CursorCu(
                    cs.flatMap { it.functions }.map { it.toHarvested() },
                    spans[file],
                    cs.firstNotNullOfOrNull { it.language },
                )
            },
            textRanges = textPartition(),
        )
    }

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
        // Two boundaries on one address make an empty run — 97 on one PE fixture — which is a real
        // statement: the file was named and claimed no bytes. Kept, since a zero-length entry is
        // exactly how the source map records a point.
        return sorted.zip(ends) { (start, source), end ->
            source?.let { start..<end to it }
        }.filterNotNull().toMap()
    }
}

/** What one pass over the stream accumulated, beyond the type store. */
data class HarvestedStream(
    /** Per source file — an N_SOL is enough to earn an entry. */
    val lineEntries: Map<GhidraSourceFile, List<LineEntry>>,
    /** Per translation unit, so its keys are exactly the files that carried an `N_SO`. */
    val cus: Map<GhidraSourceFile, CursorCu>,
    val textRanges: Map<AddressRange, GhidraSourceFile>,
)

/** One CU's share of the stream, before the harvester joins its statics and constants on. */
data class CursorCu(val functions: List<Func>, val range: AddressRange?, val language: Language?)
