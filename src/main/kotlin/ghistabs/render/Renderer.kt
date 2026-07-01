package ghistabs.render

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.StabType
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl

// Aggregates the addresses of N_SLINEs sharing a (line, codeUnit) into one annotation.
private data class SliceKey(val line: Int, val codeUnit: String)

// Dedup keys: templates instantiated many times repeat the same alias / `__val` / `__first`
// at one header line.
private data class TypeDeclKey(val line: Int, val name: String, val bodyKind: String)

private data class DeclKey(val line: Int, val name: String)

class Renderer(val typeResolver: TypeResolver, val program: Program, val decomp: DecompInterface? = null) {
    fun renderSkeleton(source: String) = RenderContext(this, source).render()
}

private class RenderContext(val renderer: Renderer, val source: String) {
    val harvest get() = renderer.typeResolver.harvest
    val program get() = renderer.program

    // A multi-CU class lands at the header its member SLINEs mostly point to, not the
    // .cpp gcc emitted the body burst in.
    private fun TypeAst.effectiveSource() =
        name?.let { renderer.typeResolver.multiSourceHeaderHints[it] } ?: id.source.filename

    private val rawFuncs = harvest.openFunctions.filter { renderer.typeResolver.functionSource[it] == source }
    private val lines = harvest.lineEntries[source].orEmpty()
    private val typeDecls = harvest.typeAsts.values
        .filter { it.effectiveSource() == source && it.name != null && it.declLine > 0 }
    private val symbols = harvest.symbolsByCu[source].orEmpty()

    private val spans = FunctionSpans.of(rawFuncs, source)

    private val maxLine = sequenceOf(
        spans.maxLine,
        lines.maxOfOrNull { it.line } ?: 0,
        typeDecls.maxOfOrNull { it.declLine } ?: 0,
        symbols.maxOfOrNull { it.declLine } ?: 0,
    ).max()

    private val canvas = Canvas(maxLine)

    private fun indentFor(line: Int) = if (spans.inFunction(line)) "    " else ""
    private fun lineTag(line: Int) = "// L" + line.toString().padStart(4)

    // A declLine past the file's activity extent flags a stale N_SOL. Body extent for CUs;
    // type-decl extent for pure-header files.
    private val activityExtent = sequenceOf(
        lines.maxOfOrNull { it.line } ?: 0,
        symbols.maxOfOrNull { it.declLine } ?: 0,
        spans.ranges.maxOfOrNull { it.endLine } ?: 0,
    ).max().takeIf { it > 0 } ?: (typeDecls.maxOfOrNull { it.declLine } ?: 0)

    // A decl at this line is misattributed (stale N_SOL) if it sits past the file's activity.
    private fun isStale(line: Int) = line > activityExtent

    private fun staleTag(line: Int) = if (isStale(line)) "${lineTag(line)} stale N_SOL?" else lineTag(line)

    fun render(): String {
        if (rawFuncs.isEmpty() && lines.isEmpty() && typeDecls.isEmpty()) return ""
        if (maxLine == 0) return ""

        emitSlineAnnotations()
        emitTypedefs()
        emitParamsAndLocals()
        emitGlobals()
        emitFunctionBraces()
        emitTypeBodies()
        reportAnomalies()
        renderer.decomp?.let(::applyDecompilation)
        return canvas.toString()
    }

    /** One `// L n @ 0xADDR[: code-unit]` annotation per (line, code-unit) group. */
    private fun emitSlineAnnotations() {
        val byKey = mutableMapOf<SliceKey, MutableSet<Address>>()
        for (entry in lines) {
            if (entry.line !in 1..maxLine) continue
            val codeUnit = entry.addr.address.render(program) ?: ""
            byKey.getOrPut(SliceKey(entry.line, codeUnit)) { sortedSetOf() } += entry.addr.address
        }
        for ((key, addrs) in byKey) {
            val tag = "L" + key.line.toString().padStart(4)
            val suffix = if (key.codeUnit.isEmpty()) "" else ": ${key.codeUnit}"
            canvas[key.line] += Fragment(
                indentFor(key.line),
                comment = "// $tag @ ${formatAddrRuns(addrs.toList(), program)}$suffix",
                kind = FragmentKind.SLINE,
            )
        }
    }

    private fun emitTypedefs() {
        val seen = mutableSetOf<TypeDeclKey>()
        for (ast in typeDecls.filter { it.declLine in 1..maxLine }.sortedBy { it.declLine }) {
            val name = ast.name ?: continue
            val body = ast.body
            if (body is TypeDecl.Struct || body is TypeDecl.Enum) continue
            if (!seen.add(TypeDeclKey(ast.declLine, name, body::class.simpleName ?: ""))) continue
            canvas[ast.declLine] += Fragment(
                indentFor(ast.declLine),
                "typedef ${body.render(harvest)} $name;",
                staleTag(ast.declLine),
                FragmentKind.TYPEDEF,
                isStale(ast.declLine),
            )
        }
    }

    private val seenDecls = mutableSetOf<DeclKey>()

    /** Emit a param/local/global decl, spreading a multi-element initializer over blank lines. */
    private fun emitDecl(
        line: Int,
        name: String,
        type: TypeDecl<GlobalTypeId>,
        role: String,
        kind: FragmentKind,
        misattributed: Boolean = false,
        initFromAddr: Address? = null,
    ) {
        if (line !in 1..maxLine || name == "this") return
        if (!seenDecls.add(DeclKey(line, name))) return
        val indent = indentFor(line)
        val decl = "${type.render(harvest)} $name"
        val tag = "${lineTag(line)} $role" + if (misattributed) "; stale N_SOL?" else ""
        val parts = initFromAddr?.let { program.initializerAt(it) }
        when {
            parts == null -> canvas[line] += Fragment(indent, "$decl;", tag, kind, misattributed)
            parts.size == 1 -> canvas[line] += Fragment(indent, "$decl = ${parts[0]};", tag, kind, misattributed)
            else -> canvas.layoutBraceBlock(line, indent, "$decl = {", tag, parts, "};", ",", ", ", kind, misattributed)
        }
    }

    // A declLine outside the host function's bracket is a stale-N_SOL signature — flag it.
    private fun emitParamsAndLocals() {
        val rangeByFunc = spans.ranges.associateBy { it.func }
        for (f in rawFuncs) {
            val span = rangeByFunc[f]?.let { it.startLine..(spans.closeLine(f) ?: it.endLine) }
            fun stale(declLine: Int) = span == null || declLine !in span
            fun emit(declLine: Int, name: String, type: TypeDecl<GlobalTypeId>, role: String) =
                emitDecl(declLine, name, type, role, FragmentKind.DECL_LOCAL, stale(declLine))
            for (p in f.params) {
                if (p.sourceFile != source) continue
                when (val d = p.body) {
                    is SymbolDecl.StackParam -> emit(p.declLine, d.name, d.type, "(param)")
                    is SymbolDecl.RegParam -> emit(p.declLine, d.name, d.type, "(reg param)")
                    else -> {}
                }
            }
            for (l in f.locals) {
                if (l.sourceFile != source) continue
                when (val d = l.body) {
                    is SymbolDecl.RegLocal -> emit(l.declLine, d.name, d.type, "(reg local)")
                    is SymbolDecl.StackLocal -> emit(l.declLine, d.name, d.type, "(stack local)")
                    else -> {}
                }
            }
        }
    }

    // Attributed by CU (`symbolsByCu`), not `s.sourceFile` — gcc emits no `N_SOL(cu)`
    // before N_GSYM, so `sourceFile` points at the last header visited.
    private fun emitGlobals() {
        for (s in symbols) {
            val suffix = when (s.recordType) {
                StabType.N_GSYM -> "(global)"
                StabType.N_LCSYM -> "(.bss static)"
                StabType.N_STSYM -> "(.data static)"
                StabType.N_ROSYM -> "(.rodata static)"
                else -> "(symbol)"
            }
            // N_GSYM has rawValue=0 (linker resolves it from the mangled name) — look it up.
            val name = (s.body as? SymbolDecl.Global)?.name ?: (s.body as? SymbolDecl.StaticVar)?.name
            val addr = when {
                s.rawValue != 0L -> program.addressFactory.defaultAddressSpace.getAddress(s.rawValue)
                name != null -> program.symbolTable.getSymbols(name).firstOrNull()?.address
                else -> null
            }
            when (val d = s.body) {
                is SymbolDecl.Global -> emitDecl(
                    s.declLine,
                    d.name,
                    d.type,
                    suffix,
                    FragmentKind.DECL_GLOBAL,
                    initFromAddr = addr,
                )
                is SymbolDecl.StaticVar ->
                    emitDecl(s.declLine, d.name, d.type, suffix, FragmentKind.DECL_GLOBAL, initFromAddr = addr)
                else -> {}
            }
        }
    }

    // Openers at startLine (self-closing decl when single-line), closers at the close line.
    private fun emitFunctionBraces() {
        for (r in spans.ranges) {
            val sig = r.func.signature(program)
            val tag = "L" + r.startLine.toString().padStart(4)
            val openText = if (r.isSingleLine) "$sig;" else "$sig {"
            val openNote = if (r.isSingleLine) "${r.func.decl.name}" else "opens ${r.func.decl.name}"
            canvas[r.startLine].fragments.add(
                0,
                Fragment(code = openText, comment = "/* $tag — $openNote */", kind = FragmentKind.FUNC_DELIM),
            )

            val closeLine = spans.closeLine(r.func) ?: continue
            if (closeLine !in 1..maxLine) continue
            val closeTag = "L" + closeLine.toString().padStart(4)
            canvas[closeLine] += Fragment(
                code = "}",
                comment = "/* $closeTag — closes ${r.func.demangledName(program)} */",
                kind = FragmentKind.FUNC_DELIM,
            )
        }
    }

    // Struct/enum bodies spread over the blank lines below the decl; opaque types fall
    // back to a one-line forward decl.
    private fun emitTypeBodies() {
        val seen = mutableSetOf<Pair<Int, String>>()
        for (ast in typeDecls.filter { it.declLine in 1..maxLine }.sortedBy { it.declLine }) {
            val line = ast.declLine
            val name = ast.name ?: continue
            val body = ast.body
            if (body !is TypeDecl.Struct && body !is TypeDecl.Enum) continue
            if (!seen.add(line to name)) continue

            val members = when (body) {
                is TypeDecl.Struct -> body.renderFull(harvest, program)
                is TypeDecl.Enum -> body.members.map { (mn, mv) -> "$mn = $mv" }
            }
            val open = when (body) {
                is TypeDecl.Struct -> {
                    val bases = body.bases.takeIf { it.isNotEmpty() }
                        ?.joinToString(", ", prefix = " : ") {
                            "${it.access.name.lowercase()} ${it.type.render(harvest)}"
                        }
                        .orEmpty()
                    "${body.kind.cxxKeyword()} $name$bases {"
                }
                is TypeDecl.Enum -> "enum $name {"
            }
            val sizeNote = when (body) {
                is TypeDecl.Struct -> "/* ${body.sizeBytes} bytes */"
                is TypeDecl.Enum -> "/* ${body.members.size} members */"
            }
            val (itemSuffix, sep) = when (body) {
                is TypeDecl.Struct -> "" to " "
                is TypeDecl.Enum -> "," to ", "
            }
            val indent = indentFor(line)
            if (members.isNotEmpty()) {
                canvas.layoutBraceBlock(
                    line, indent, open, staleTag(line), members, "}; $sizeNote", itemSuffix, sep,
                    FragmentKind.TYPE_BODY, isStale(line),
                )
            } else {
                val keyword = if (body is TypeDecl.Struct) body.kind.cxxKeyword() else "enum"
                canvas[line] +=
                    Fragment(indent, "$keyword $name; $sizeNote", staleTag(line), FragmentKind.TYPE_BODY, isStale(line))
            }
        }
    }

    /**
     * Replace each function's span with its decompilation. A fragment in the span is
     * dropped when the decomp already shows it ([FragmentKind.subsumedByDecomp]) or when
     * it's misattributed; every other stray (a type decl / global gcc mis-filed here) is
     * demoted to a `// stray:` comment on the close line — never code, so it can't force
     * a cram. Decomp longer than the span crams its own overflow onto the last line.
     */
    private fun applyDecompilation(decomp: DecompInterface) {
        // Where a decl shares a line with real content, the misattributed one is noise.
        for (b in canvas.multiFragmentLines()) b.fragments.removeAll { it.misattributed }
        for (r in spans.ranges) {
            val closeLine = spans.closeLine(r.func) ?: continue
            if (closeLine <= r.startLine) continue
            val ghFunc = program.functionManager.getFunctionAt(r.func.addr.address) ?: continue
            val cCode = runCatching { decomp.decompileFunction(ghFunc, 30, TaskMonitor.DUMMY) }
                .getOrNull()?.decompiledFunction?.c ?: continue
            val cLines = cleanDecompLines(cCode)

            val strays = mutableListOf<Fragment>()
            for (line in r.startLine..closeLine) {
                canvas[line].fragments.removeAll { f ->
                    if (!f.kind.subsumedByDecomp && !f.misattributed) strays += f
                    true
                }
            }
            val available = closeLine - r.startLine + 1
            if (cLines.size <= available) {
                cLines.forEachIndexed { i, l ->
                    canvas[r.startLine + i] +=
                        Fragment(code = l, kind = FragmentKind.DECOMP)
                }
            } else {
                for (i in 0 until available - 1) {
                    canvas[r.startLine + i] += Fragment(code = cLines[i], kind = FragmentKind.DECOMP)
                }
                val rest = cLines.subList(available - 1, cLines.size)
                    .map { it.trim().trimEnd(';') }
                    .filter { it.isNotEmpty() }
                canvas[closeLine] += Fragment(code = rest.joinToString("; ") + ";", kind = FragmentKind.DECOMP)
            }
            for (s in strays) {
                val text = listOfNotNull(s.code, s.comment).joinToString("  ")
                canvas[closeLine] += Fragment(comment = "// stray: $text")
            }
        }
    }

    // Diagnostic: a function/type/global landing inside another function's interior is
    // suspect. Deduped; overload sets on the same demangled name are skipped.
    private fun reportAnomalies() {
        val anomalies = sortedSetOf<String>()
        for (r in spans.ranges) {
            val closeLine = spans.closeLine(r.func) ?: continue
            val interior = (r.startLine + 1) until closeLine
            val fname = r.func.demangledName(program)
            val where = "inside $fname [L${r.startLine}..L$closeLine]"
            for (g in spans.ranges) {
                if (g.func === r.func) continue
                val gname = g.func.demangledName(program)
                if (gname == fname) continue
                if (g.startLine in interior) {
                    anomalies += "skeleton[$source]: function $gname opens at L${g.startLine} $where"
                }
                if (g.endLine in interior && g.startLine !in interior) {
                    anomalies += "skeleton[$source]: function $gname closes at L${g.endLine} $where"
                }
            }
            for (ast in harvest.typeAsts.values) {
                if (ast.id.source.filename != source || ast.declLine !in interior) continue
                val name = ast.name ?: continue
                anomalies += "skeleton[$source]: type $name declared at L${ast.declLine} $where"
            }
            for (s in symbols) {
                if (s.declLine !in interior) continue
                val nm = (s.body as? SymbolDecl.Global)?.name ?: (s.body as? SymbolDecl.StaticVar)?.name ?: continue
                anomalies += "skeleton[$source]: global/static $nm at L${s.declLine} $where"
            }
        }
        anomalies.forEach(::println)
    }
}

/** Collapse addresses of back-to-back code units into `0xS-0xE` runs, comma-joined. */
private fun formatAddrRuns(addrs: List<Address>, program: Program): String {
    if (addrs.isEmpty()) return ""
    val sorted = addrs.sortedBy { it.offset }
    val runs = mutableListOf<Pair<Address, Address>>()
    var runStart = sorted[0]
    var runEnd = sorted[0]
    for (cur in sorted.drop(1)) {
        val inst = program.listing.getInstructionAt(runEnd)
        val expectedNext = inst?.next?.address
            ?: program.listing.getCodeUnitAt(runEnd)?.takeIf { it.length > 0 }?.let { runEnd.add(it.length.toLong()) }
        if (cur == expectedNext) {
            runEnd = cur
        } else {
            runs += runStart to runEnd
            runStart = cur
            runEnd = cur
        }
    }
    runs += runStart to runEnd
    fun hex(a: Address) = "0x" + a.offset.toString(16).padStart(8, '0')
    return runs.joinToString(", ") { (s, e) -> if (s == e) hex(s) else "${hex(s)}-${hex(e)}" }
}

/** Drop the decomp's leading header/warning comments and fold a lone `{` onto the signature. */
private fun cleanDecompLines(cCode: String): List<String> {
    val raw = cCode.trim('\n').split('\n').toMutableList()
    while (raw.isNotEmpty()) {
        val l = raw.first().trimStart()
        val drop = (l.startsWith("/*") && l.trimEnd().endsWith("*/")) || l.isEmpty()
        if (!drop) break
        raw.removeAt(0)
    }
    val out = mutableListOf<String>()
    for (l in raw) {
        if (l.trim() == "{" && out.isNotEmpty()) {
            var idx = out.size - 1
            while (idx > 0 && out[idx].isBlank()) idx--
            out[idx] = out[idx].trimEnd() + " {"
            while (out.size - 1 > idx) out.removeAt(out.size - 1)
        } else {
            out += l
        }
    }
    return out
}
