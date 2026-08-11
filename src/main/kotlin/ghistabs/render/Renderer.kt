package ghistabs.render

import ghidra.app.decompiler.ClangToken
import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions.Companion.stabsTypedefsShortened
import ghistabs.harvest.Func
import ghistabs.harvest.HarvestIndex
import ghistabs.importer.AddressResolver
import ghistabs.materialize.TemplateNameShortener
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.runTransaction
import java.io.Closeable
import java.io.File
import java.util.*

enum class Mode {
    SKELETON,
    DECOMPILE,

    // Elide gcc SjLj exception scaffolding (the __Unwind_SjLj_* calls, personality store, and the
    // per-call-site index writes) from decompilation output. No-op on DWARF-EH (ELF) binaries.
    ELIDE_SJLJ,
}

class Renderer(
    val index: HarvestIndex,
    val program: Program,
    val mode: Mode,
    val resolver: AddressResolver,
    // Off for a render meant to be compiled or diffed against real source, where a trailing block of
    // declarations that have no line is noise.
    val showDisplaced: Boolean = true,
    // Annotate each local with the storage gcc gave it. Off by default: it is a property of the
    // compiled code, not of the source being reconstructed.
    val showStorage: Boolean = false,
) : Closeable {
    /**
     * Collapses long template spellings (`basic_string<char,…>` → `string`) across *everything* the
     * render emits, declarations and decompiled code alike. Shortening only the AST half is what left
     * `ofstream os;` next to `basic_ofstream<char,std::char_traits<char>> os;` in one merged head.
     *
     * Not a render setting: it follows the import's, because the two halves come from different places
     * and only agree when they agree with each other. Shortened at import means the datatypes were
     * renamed, so the decompiler already hands us short names and substituting is a no-op the AST side
     * needs; not shortened means long names in the decompiler, which the AST side must then match.
     */
    val shortener by lazy {
        if (program.stabsTypedefsShortened) harvestTemplateShortener() else TemplateNameShortener(emptyMap())
    }

    // `also`, not `apply`: inside `apply` the receiver's own (null) `program` property would shadow
    // the constructor param, so openProgram(program) would be handed null.
    val decomp = if (mode != Mode.SKELETON) DecompInterface().also { it.openProgram(program) } else null

    val sources get() = index.sources

    // A function is decompiled once for the whole run, not once per file that renders part of it: with
    // inlined code now placed in the header it came from, one std::string method is wanted by every
    // file that inlines it, and decompilation is ~all of the runtime.
    private val decompiled = mutableMapOf<Address, Decompiled>()

    /** One function's decompilation: the rows the render places, and the dataflow behind them. */
    class Decompiled(val lines: List<DecompLine>, val flow: VarFlow)

    fun decompile(func: Func) = decompiled.getOrPut(func.addr) {
        val results = program.functionManager.getFunctionAt(func.addr)?.let { ghFunc ->
            runCatching { decomp?.decompileFunction(ghFunc, 30, TaskMonitor.DUMMY) }.getOrNull()
        }
        // Folded onto the function's *own* source, not the file asking: that only governs which locals
        // drop out of the head fold, and the head is used only where the function is defined.
        val lines = with(index) { func.source() }?.let { own ->
            // Same address→line lookup [Region] membership uses, narrowed to the function's own
            // source: two branches are only in source order against one file's line numbering.
            val slines = func.lineEntries.filter { it.source == own }.sortedBy { it.addr }
            results?.compressedDecompLines(own, func, ::spell, mode == Mode.ELIDE_SJLJ)
                // Before the render splits it into regions: swapping branches moves their anchors,
                // and the anchors are what every later pass places by.
                ?.uninvertConditions { line -> line.address?.let { a -> slines.lastOrNull { it.addr <= a }?.line } }
        }
        Decompiled(lines.orEmpty(), results?.varFlow() ?: VarFlow(emptyMap(), emptyMap()))
    }

    /**
     * How a decompiler token is spelled in the render: its type name shortened to whatever typedef
     * the import installed, and the `~` Ghidra puts inside a vtable-pointer's name — `PTR_~runtime
     * _error_0043ecfc` — respelled, `~` not being an identifier character (12 of unbouniaf's 39
     * remaining structural errors).
     *
     * Per token rather than over the assembled row. A row's offsets then index its final text, and
     * the `~` rule sees one name at a time: a destructor call (`p->~string()`) puts its `~` at the
     * start of its own token and a bitwise not is an operator token, so neither can be caught by a
     * rule about what precedes the `~` in the row.
     */
    fun spell(token: ClangToken): String = spelled.getOrPut(token) {
        shortener.substitute(token.text).let { if ('~' in it) it.respellTilde() else it }
    }

    // Each row asks for its tokens' spellings several times over (once to size the row, once per
    // offset, once for the text) and the substitution is a regex sweep.
    private val spelled = IdentityHashMap<ClangToken, String>()

    fun renderSkeleton(source: String) = FileRenderer(this, source).render()

    /**
     * Render every source into [dir], one file per source (named from the source path). Wraps the
     * render in a transaction — it defines terminated strings at undefined pointer targets it meets
     * while rendering constant values. Returns the number of files written; stops early if [monitor]
     * is canceled.
     */
    fun renderAll(dir: File, monitor: TaskMonitor = TaskMonitor.DUMMY): Int {
        monitor.initialize(sources.size.toLong())
        dir.mkdirs()
        return program.runTransaction("stabs-render-all") {
            sources.asSequence()
                .map { it to renderSkeleton(it) }
                .takeWhile { runCatching { monitor.incrementProgress() }.isSuccess }
                // A source with nothing to show writes no file. Said out loud rather than skipped in
                // silence: an empty render is either a file gcc mentioned and never described, or a
                // bug in attribution, and the difference is only visible if the name is named.
                .onEach { (source, text) -> if (text.isBlank()) println("render[$source]: empty, no file written") }
                .filter { (_, text) -> text.isNotBlank() }
                .onEach { (source, text) ->
                    File(dir, outputPath(index.locate(source))).apply { parentFile?.mkdirs() }.writeText(text)
                }
                .count()
        }
    }

    /**
     * Shortener seeded from the stabs typedefs themselves (typedef name → aliased type's name), for the
     * skeleton renderer, which spells types from the harvest AST rather than the DTM (so the DTM
     * shortening pass doesn't reach it). Only typedefs whose target is a template instantiation (has a
     * `<`) are used — that excludes base-type aliases (`fpos_t`→`longlong`) without DataType lookups.
     */
    fun harvestTemplateShortener(): TemplateNameShortener {
        fun targetName(decl: TypeDecl<GlobalTypeId>): String? = when (decl) {
            is TypeDecl.Ref -> index.byId(decl.id)?.name
            is TypeDecl.XRef -> decl.tagName
            is TypeDecl.InlineDef -> targetName(decl.inner)
            else -> null
        }

        return TemplateNameShortener(
            index.allTypes.mapNotNull { ast ->
                ast.name?.let { name ->
                    targetName(ast.body)?.takeIf { '<' in it && it.length > name.length }?.let { name to it }
                }
            }.toMap(),
        )
    }

    // We own the DecompInterface, so terminate its process rather than just detaching the program.
    override fun close() {
        decomp?.dispose()
    }
}
