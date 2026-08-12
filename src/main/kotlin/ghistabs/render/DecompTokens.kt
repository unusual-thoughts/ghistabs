package ghistabs.render

import ghidra.app.decompiler.*
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghistabs.Correction
import ghistabs.harvest.BlockScope
import ghistabs.harvest.Func
import ghistabs.harvest.GhidraSourceFile
import ghistabs.harvest.blockAt
import ghistabs.parse.SymbolDecl

/** How a token is spelled in the render — see [Renderer.spell] for what the renderer substitutes. */
typealias Spelling = (ClangToken) -> String

/** A token and the offset its spelling takes in the row it was rendered into. */
data class Placed(val token: ClangToken, val at: Int)

/** A `{` or `}`, and where it sits in its row. */
data class Brace(val char: Char, val at: Int)

/** A point an over-long row may be broken at, and the paren nesting it sits at. */
data class Cut(val at: Int, val depth: Int)

/** The rows of the two branches of an `if`. */
data class Branches(val then: IntRange, val otherwise: IntRange)

/**
 * A rendered decompiler line, the lowest instruction address its tokens map to (null for the folded
 * header / a structural line), and its indent [depth] — the line's own structural nesting level from
 * Ghidra (0 = the signature/close-brace column), used verbatim as the leading space count.
 *
 * [block] is the innermost lexical block covering *every* address the line touches, null when they
 * disagree or none is bracketed. It is the only thing that knows where an inlined body ends: the
 * N_SLINE table says which file each address came from but draws no boundary around the region.
 *
 * Everything after [declares] is what the token tree said about the row, as offsets into [text] and
 * row numbers: the braces, the condition and branches of an `if`, the `this` parameter, where an
 * over-long row may be broken. The characters can answer none of it — a `{` in a string literal
 * counts as a block, a row carrying several `if`s cannot say which one a trailing brace belongs to,
 * an `&&` inside a call's arguments looks like a split point — and the offsets index the *final*
 * text, the spelling substitutions having been applied per token before the row was assembled.
 *
 * Read once, where the tokens are still in hand; the tokens themselves are not kept, so a row stays
 * a plain value and a whole program's decompiler markup is not held live behind the render.
 */
data class DecompLine(
    val text: String,
    val address: Address?,
    val depth: Int = 0,
    val block: BlockScope? = null,
    // Every name the folded head brings into scope — its prototype's parameters and its declaration
    // block's locals. Empty on any other line. Read from the token stream, so it stays right however
    // the declarations are grouped or rendered; it is what lets the stabs locals merge into the head
    // instead of contending for rows the body already holds.
    val declares: Set<String> = emptySet(),
    /** The row's braces, in order, each where it sits. */
    val braces: List<Brace> = emptyList(),
    /** Range within [text] of the condition of an `if (…) {` that opens a block at the row's end. */
    val ifCondition: IntRange? = null,
    /** Which rows the two branches of that `if` took, when it has a plain `else`. */
    val branches: Branches? = null,
    /** Where the implicit object parameter Ghidra prints as an explicit `this` appears. */
    val thisAt: List<IntRange> = emptyList(),
    /** Where an over-long row may be broken — just past each `&&`/`||`, with its paren depth. */
    val booleanCuts: List<Cut> = emptyList(),
    /** The folded head only: what a legal C++ member definition must leave out. See [memberCutsOf]. */
    val memberCuts: List<IntRange> = emptyList(),
    /**
     * The folded head only: the signature, without the declaration block folded into it. What
     * identifies the function among those starting on one source line — the declaration block does
     * not, gcc's aliased copies being decompiled separately and so named per copy.
     */
    val prototype: String? = null,
    /** Where a call passes Ghidra's explicit this-argument. See [thisArguments]. */
    val thisArgs: List<IntRange> = emptyList(),
) {
    /**
     * This row with `f(this,x)` written `f(x)`, for a body rendering inside the member it belongs to.
     *
     * [memberCutsOf] already drops the explicit parameter from the *definition*, so leaving the call
     * sites alone made the two halves of one render contradict each other — `find_slt(this,uVar1)`
     * calling a `find_slt(which_slt)` — and neither compiles. Not applied to an inlined stretch: that
     * is wrapped as a *free* function where `this` is a real parameter (renamed by [renameThis]), and
     * dropping the argument there would call a member function with nothing to call it on.
     */
    fun withoutThisArguments() = thisArgs.sortedByDescending { it.first }.fold(this) { row, cut -> row.without(cut) }

    /** This row as a member definition: [memberCuts] taken out, every offset moved with them. */
    fun asMemberDefinition() = memberCuts.sortedByDescending { it.first }.fold(this) { row, cut -> row.without(cut) }

    private fun without(cut: IntRange): DecompLine {
        val width = cut.last + 1 - cut.first
        fun shift(at: Int) = if (at > cut.last) at - width else at
        return copy(
            text = text.removeRange(cut),
            braces = braces.filterNot { it.at in cut }.map { it.copy(at = shift(it.at)) },
            ifCondition = ifCondition?.let { shift(it.first)..<shift(it.last + 1) },
            thisAt = thisAt.filterNot { it.first in cut }.map { shift(it.first)..<shift(it.last + 1) },
            booleanCuts = booleanCuts.filterNot { it.at in cut }.map { it.copy(at = shift(it.at)) },
            memberCuts = emptyList(),
            thisArgs = thisArgs.filterNot { it.first in cut }.map { shift(it.first)..<shift(it.last + 1) },
        )
    }

    /** [text] with `this` spelled [name], for a body lifted out of the member it was written in. */
    fun renameThis(name: String) =
        thisAt.sortedByDescending { it.first }.fold(text) { s, at -> s.replaceRange(at, name) }

    /**
     * The row with its `if` condition negated, every offset moved by what the insertion displaced —
     * so the row's structure keeps describing its text rather than the text it used to have.
     */
    fun negate(condition: IntRange): DecompLine {
        fun shift(at: Int) = at + when {
            at > condition.last -> 3
            at >= condition.first -> 2
            else -> 0
        }
        return copy(
            text = text.replaceRange(condition, "!(${text.substring(condition)})"),
            braces = braces.map { it.copy(at = shift(it.at)) },
            ifCondition = condition.first..condition.last + 3,
            thisAt = thisAt.map { shift(it.first)..<shift(it.last + 1) },
            booleanCuts = booleanCuts.map { it.copy(at = shift(it.at)) },
        )
    }

    companion object {
        /**
         * A row we emit ourselves — braces a run was missing, a wrapper head, an inlining marker.
         * Nothing decompiled it, so its own text is the only thing that knows its braces; it holds
         * no string literals and no `if`, being ours.
         */
        fun synthetic(text: String) = DecompLine(
            text,
            null,
            braces = text.mapIndexedNotNull { i, c -> Brace(c, i).takeIf { c in "{}" } },
        )
    }
}

/** The nearest ancestor group of this token that is a [cls] (e.g. ClangStatement, ClangFuncProto). */
private fun <T : ClangNode> ClangToken.ancestor(cls: Class<T>): T? {
    var node: ClangNode? = Parent()
    while (node != null) {
        if (cls.isInstance(node)) return cls.cast(node)
        node = node.Parent()
    }
    return null
}

private fun ClangToken.inside(cls: Class<out ClangNode>) = ancestor(cls) != null

private fun ClangNode.children() = (0..<numChildren()).map { Child(it) }

private fun ClangNode.leaves() = mutableListOf<ClangNode>().also { flatten(it) }.filterIsInstance<ClangToken>()

// A `beginBlock`/`endBlock` group, which `printc.cc` emits as a plain group — `ClangStatement`,
// `ClangVariableDecl`, `ClangReturnType` and `ClangFuncProto` are distinct subclasses.
private fun ClangNode.asBlock() = (this as? ClangTokenGroup)?.takeIf { it::class == ClangTokenGroup::class }

private fun ClangNode?.spells(text: String) = (this as? ClangToken)?.text == text

// Block-nesting level: the shallowest token's count of enclosing block groups. Equal for a wrapped
// line's continuations and their header; one deeper for a nested statement.
private fun ClangLine.blockDepth() = significant().minOfOrNull { tok ->
    generateSequence(tok.Parent()) { it.Parent() }.count { it.asBlock() != null }
} ?: 0

// The x86 calling-convention keywords Ghidra prints in a prototype; noise in a source skeleton.
// Derived spellings included: StructReturnAnalyzer installs `__thiscall_memret`/`__cdecl_regret` as
// ordinary prototype models, so Ghidra prints them here exactly like a stock convention.
private val CALLING_CONVENTIONS = setOf("__thiscall", "__cdecl", "__stdcall", "__fastcall", "__vectorcall")
    .let { base -> base + base.flatMap { c -> Correction.entries.map { c + it.suffix } } }

// Tokens carrying text, minus line breaks and the calling-convention keyword (with the one blank
// that trails it, so `ushort __thiscall Foo::m` reads `ushort Foo::m`, not `ushort  Foo::m`).
private fun ClangLine.content(): List<ClangToken> = buildList {
    var dropTrailingBlank = false
    for (t in allTokens) {
        when {
            t is ClangBreak -> {}
            t.text in CALLING_CONVENTIONS -> dropTrailingBlank = true
            dropTrailingBlank && !t.isSignificant -> dropTrailingBlank = false
            else -> add(t).also { dropTrailingBlank = false }
        }
    }
}

private val ClangToken.isSignificant get() = text.isNotBlank()
private fun ClangLine.significant() = content().filter { it.isSignificant }
private fun ClangNode.significantLeaves() = leaves().filter { it.isSignificant }
private fun List<Placed>.significant() = filter { it.token.isSignificant }

/**
 * Each of this line's content tokens with the offset its spelling takes in the line's *trimmed*
 * render — the form a row carries. The lead is whatever the trim takes off the front, which is the
 * indent plus any leading spacer token.
 */
private fun ClangLine.placed(spell: Spelling): List<Placed> {
    val full = indentString + content().joinToString("") { spell(it) }
    var at = indentString.length - (full.length - full.trimStart().length)
    return content().map { t -> Placed(t, at).also { at += spell(t).length } }
}

private fun ClangLine.rendered(spell: Spelling) = (indentString + content().joinToString("") { spell(it) }).trimEnd()

/**
 * What separates a rejoined fragment from the one [previous] left off at: one space, standing in for
 * the one the break replaced — except between a function's name and its own parameter list, which is
 * one construct with nothing between the two, and which the pretty-printer breaks at because
 * `openParen` opens a group. Without the exception a signature Ghidra wrapped after the name comes
 * back as `name (…)`; with it applied to every paren, `a ||(b)` and `f(x,(y))` lose theirs.
 */
private fun ClangLine.rejoin(previous: ClangLine) = if (previous.significant().lastOrNull() is ClangFuncNameToken &&
    significant().firstOrNull().let { it is ClangSyntaxToken && it.open >= 0 }
) {
    ""
} else {
    " "
}

/** The fragments a wrapped logical line was rejoined from, each token at its offset in the join. */
private fun List<ClangLine>.placed(spell: Spelling): List<Placed> {
    var base = 0
    return flatMapIndexed { i, line ->
        base += if (i == 0) 0 else line.rejoin(this[i - 1]).length
        line.placed(spell).map { it.copy(at = base + it.at) }.also { base += line.rendered(spell).trim().length }
    }
}

private fun List<ClangLine>.rendered(spell: Spelling) = mapIndexed { i, line ->
    (if (i == 0) "" else line.rejoin(this[i - 1])) + line.rendered(spell).trim()
}.joinToString("")

// A brace is a ClangSyntaxToken, so a `{` reaching the text from a string literal or a comment — which
// arrive as other token kinds — is not one, the way a character count would have it.
private fun ClangToken.isBrace() = this is ClangSyntaxToken && DecompilerUtils.isBrace(this)

private fun List<Placed>.braces() = filter { it.token.isBrace() }.map { Brace(it.token.text.first(), it.at) }

/**
 * Range within the row's text of the condition of an `if (…) {` that opens a block at its end.
 *
 * The `if` is a [ClangOpToken] (`printc.cc` emits it `tagOp(KEYWORD_IF, …, op)`) and its condition is
 * delimited by a real paren pair — `ClangSyntaxToken.getOpen()`/`getClose()` — so a row carrying
 * several statements, which every row does here (the folded head, rejoined continuations), gives up
 * exactly the last `if`'s condition. Walking parens back through the characters could not: on
 * `… { if (a != false) { if (b == c) {` a greedy match spanned both conditions and one brace.
 */
private fun List<Placed>.ifCondition(): IntRange? {
    val toks = significant()
    if (toks.lastOrNull()?.token?.let { it.isBrace() && it.text == "{" } != true) return null
    val keyword = toks.indexOfLast { it.token is ClangOpToken && it.token.text == KEYWORD_IF }
        .takeIf { it >= 0 } ?: return null
    val open = toks[keyword + 1].token as? ClangSyntaxToken ?: return null
    val id = open.open.takeIf { it >= 0 } ?: return null
    // The closer must be the row's second-to-last token: anything between it and the `{` (a `goto`,
    // another statement) means this brace is not the one this `if` opens.
    val close = toks[toks.size - 2].takeIf { (it.token as? ClangSyntaxToken)?.close == id } ?: return null
    return (toks[keyword + 1].at + 1)..<close.at
}

private val EMPTY_BLOCK = listOf('{', '}')

/* An already-closed empty block at the end of a decompiled line — Ghidra spells it `{ }` or `{}` */
fun List<Brace>.isEmptyBlock() = map(Brace::char) == EMPTY_BLOCK

/**
 * Offsets just past each shallowest-depth `&&`/`||` — the top-level boolean joins, the readable
 * points to break an over-long row at. Empty where the row has none at any depth.
 *
 * The operators are [ClangOpToken]s and the depth comes from the paren and bracket tokens, so an
 * `&&` inside a call's arguments is nested rather than top-level and one inside a string literal is
 * not an operator at all — neither of which a character scan could tell.
 */
private fun List<Placed>.booleanCuts(): List<Cut> {
    val toks = significant()
    var depth = 0
    return toks.mapIndexedNotNull { i, p ->
        when (p.token.text) {
            "(", "[" -> null.also { depth++ }
            ")", "]" -> null.also { depth-- }
            "&&", "||" -> if (p.token is ClangOpToken) toks.getOrNull(i + 1)?.let { Cut(it.at, depth) } else null
            else -> null
        }
    }
}

/**
 * The rows of the two branches of the `if` whose opening brace is [brace], from the groups
 * `emitBlockIf` puts them in: `beginBlock(getBlock(1))` for the then branch and
 * `beginBlock(getBlock(2))` for the else, each a plain [ClangTokenGroup] sibling of the brace that
 * opens it. Walking rows and counting brace depth found the same thing only as long as every brace
 * on a row was a block and the separator was spelled the way the pass expected.
 *
 * The `else`'s own brace sits either before its group or, where `printc.cc` had queued a *pending*
 * brace to merge an `else if` and then found no `if` to merge with, as that group's first token.
 * Either way the branch is the group; what tells a real chain apart is that its group opens with the
 * `if` instead — which is why a plain `else` is recognised by the brace being *somewhere* and not by
 * matching `} else {` against `} else if (`.
 */
private fun branchesAt(brace: ClangToken, rowOf: Map<ClangLine, Int>): Branches? {
    val siblings = (brace.Parent() ?: return null).children()
        .filter { it !is ClangBreak && (it !is ClangToken || it.isSignificant) }
    val i = siblings.indexOfFirst { it === brace }.takeIf { it >= 0 } ?: return null
    val then = siblings.getOrNull(i + 1)?.asBlock() ?: return null
    if (!siblings.getOrNull(i + 2).spells("}") || !siblings.getOrNull(i + 3).spells(KEYWORD_ELSE)) return null
    val braced = siblings.getOrNull(i + 4).spells("{")
    val otherwise = (if (braced) siblings.getOrNull(i + 5) else siblings.getOrNull(i + 4))
        ?.asBlock()?.takeIf { braced || it.wrapsItsOwnBraces() } ?: return null
    return Branches(
        then.rows(rowOf) ?: return null,
        otherwise.rows(rowOf, unwrap = !braced) ?: return null,
    )
}

// A group holding its own delimiters: the pending brace was printed inside it, and the nested
// `emitBlockIf` that owns that brace closes it inside too.
private fun ClangNode.wrapsItsOwnBraces() = significantLeaves()
    .let { it.firstOrNull().spells("{") && it.lastOrNull().spells("}") }

// The rows the group's tokens landed on — minus its own delimiters where it carries them, those
// sitting on the separator and closing rows, which belong to neither branch.
private fun ClangNode.rows(rowOf: Map<ClangLine, Int>, unwrap: Boolean = false): IntRange? {
    val inner = significantLeaves().let { if (unwrap) it.drop(1).dropLast(1) else it }
    return inner.mapNotNull { rowOf[it.lineParent] }.ifEmpty { null }?.let { it.min()..it.max() }
}

private const val KEYWORD_IF = "if"
private const val KEYWORD_ELSE = "else"

private fun ClangLine.addresses(): List<Address> = content().mapNotNull { it.minAddress }
private fun ClangLine.address(): Address? = addresses().minOrNull()
private fun ClangLine.stackOffsets(): List<Long> = content()
    .filterIsInstance<ClangVariableToken>()
    .mapNotNull { it.varnode?.address?.takeIf { a -> a.isStackAddress }?.offset }

private const val SJLJ_PERSONALITY = "___gxx_personality_sj0"
private val SJLJ_CALLS = setOf("__Unwind_SjLj_Register", "__Unwind_SjLj_Unregister")

/**
 * ClangLines that are gcc SjLj exception scaffolding: the `__Unwind_SjLj_*` register/unregister
 * calls, the personality-routine store, and every write to the write-only call-site-index slot —
 * the SjLj context base + 4, base being the `&ctx` passed to `__Unwind_SjLj_Register`. Empty unless
 * the SjLj personality routine appears, so DWARF-EH (ELF) binaries, which keep unwinding out of the
 * code, match nothing.
 */
private fun sjljScaffolding(lines: List<ClangLine>): Set<ClangLine> {
    if (lines.none { l -> l.content().any { it.text == SJLJ_PERSONALITY } }) return emptySet()
    // The `&ctx` passed to __Unwind_SjLj_Register is an address-of, so its ClangVariableToken has no
    // stack varnode — we can't read the context offset from it. Identify the call-site index by its
    // signature instead: it's the one stack slot written on many lines as the sole variable (SjLj
    // stores it before every protected call and never reads it).
    val callSiteOffset = lines
        .mapNotNull { it.stackOffsets().singleOrNull() }
        .groupingBy { it }.eachCount()
        .filterValues { it >= 3 }
        .maxByOrNull { it.value }?.key
    return lines.filterTo(mutableSetOf()) { line ->
        line.content().any { (it is ClangFuncNameToken && it.text in SJLJ_CALLS) || it.text == SJLJ_PERSONALITY } ||
            (callSiteOffset != null && line.stackOffsets().singleOrNull() == callSiteOffset)
    }
}

// A line's role, read from its tokens' kinds and tree position — never from the rendered characters.
private fun ClangLine.isComment() = significant().let { it.isNotEmpty() && it.all { t -> t is ClangCommentToken } }
private fun ClangLine.isCode() = content().any { it.inside(ClangStatement::class.java) }
private fun ClangLine.isSignature() = content().any { it.inside(ClangFuncProto::class.java) }

// A local-variable declaration line — a `ClangVariableDecl` group, not merely a line carrying a
// type token (a `(uint)` cast in `else if ((uint)i < 4)` would false-positive that). The signature's
// params are also ClangVariableDecls, so exclude it.
private fun ClangLine.isDeclaration() = !isSignature() && content().any { it.inside(ClangVariableDecl::class.java) }

// A wrap fragment that is only trailing punctuation (`;`/`)`/`.`/`,`) — Ghidra broke it off the end
// of a long statement with no extra indent, so it carries no address and the depth-based rejoin can't
// see it. Never a statement of its own, so it rejoins its predecessor unconditionally. Braces aren't
// in the set, so a `}` still keeps its own row.
private val TRAILING_PUNCTUATION = setOf(";", ")", ".", ",", "->")
private fun ClangLine.isTrailingPunctuation() =
    significant().let { toks -> toks.isNotEmpty() && toks.all { it.text in TRAILING_PUNCTUATION } }

// A declaration of a local gcc attributed to a header: its lexical block was inlined from one, so it
// is declared in that header's own render and has no business in this file's. Ghidra dedups colliding
// names with a `_<n>` suffix, so the base name is what matches; a name shared with a this-file local
// stays, the two being indistinguishable here. The suffix is Ghidra's spelling of one identifier, not
// a shape read out of a rendered row.
private val DEDUP_SUFFIX = Regex("_\\d+$")

private fun ClangLine.declaresForeign(func: Func, source: GhidraSourceFile): Boolean {
    val name = significant().lastOrNull { it is ClangVariableToken }?.text?.replace(DEDUP_SUFFIX, "") ?: return false
    val matching = func.locals.filter { (it.body as? SymbolDecl.Local)?.name == name }
    return matching.isNotEmpty() && matching.all { it.sourceFile != source }
}

/**
 * The implicit object parameter Ghidra prints as an explicit one. A *variable token* spelled `this`:
 * `this` is a C++ keyword, so no other variable can be called it, and what makes the parameter
 * illegal in a member definition is exactly that spelling. `DecompilerUtils.isThisParameter` answers
 * the neighbouring question — whether Ghidra's model marks it an auto-parameter — and misses the
 * member functions where the decompiler prints `this` without having mapped it to one, which on the
 * corpus is any whose storage we overrode (`FileSystemEntry::children`).
 */
private fun ClangToken.isThis() = this is ClangVariableToken && text == THIS

/**
 * Decompiler output with the leading declaration block folded onto the signature line and
 * same-typed locals grouped (`string *a; string *b;` → `string *a,*b;`), so statements start at
 * the top of the span instead of one-decl-per-line pushing them down. Locals gcc attributed to a
 * header drop out of the fold — they are declared in that header's own render. Every line's role and
 * each declaration's type are read from the clang token stream — comment banners by ClangCommentToken,
 * statements by ClangStatement ancestry, the signature by ClangFuncProto, declarations by
 * ClangVariableDecl ancestry, K&R nesting by the line's own `indent` — so nothing is guessed from
 * the rendered characters.
 *
 * [spell] is applied per token, not to the assembled row, so every offset a row carries is an offset
 * into its final text.
 */
fun DecompileResults.compressedDecompLines(
    source: GhidraSourceFile,
    func: Func,
    spell: Spelling = { it.text },
    elideSjlj: Boolean = false,
): List<DecompLine> {
    // exception in box2d, cCodeMarkup was null for some function. should log.
    val raw = DecompilerUtils.toLines(cCodeMarkup ?: return listOf())
    val victims = if (elideSjlj) sjljScaffolding(raw) else emptySet()
    // Drop Ghidra's blank lines outright — we place with our own spacing, and a stray blank
    // otherwise surfaces as a bare `// ⇐ L NN` tag when a run breaks into the gap below the span.
    val lines = raw
        .filterNot { it in victims || it.significant().isEmpty() }
        .dropWhile { it.isComment() }
    val ghFunction = function

    // Everything a row's tokens say about it. Shared with the folded head, which is a row like any
    // other here: gcc gives a leading `if` no ClangStatement, so it lands in the head's prefix rather
    // than the body, and the pass that uninverts branches reads the head's `if` like any row's.
    fun structure(placed: List<Placed>, rowOf: Map<ClangLine, Int>) = placed.significant().lastOrNull()
        ?.token?.takeIf { it.isBrace() && it.text == "{" }
        .let { brace -> Triple(placed.ifCondition(), brace?.let { branchesAt(it, rowOf) }, placed.booleanCuts()) }

    fun row(g: List<ClangLine>, rowOf: Map<ClangLine, Int>): DecompLine {
        val placed = g.placed(spell)
        val (condition, branches, cuts) = structure(placed, rowOf)
        return DecompLine(
            g.rendered(spell),
            g.first().address(),
            g.first().indent,
            g.flatMap { it.addresses() }.map { func.blockAt(it) }.distinct().singleOrNull(),
            braces = placed.braces(),
            ifCondition = condition,
            branches = branches,
            thisAt = placed.thisAt(),
            booleanCuts = cuts,
            thisArgs = placed.thisArguments(),
        )
    }

    val bodyStart = lines.indexOfFirst { it.isCode() }
    if (bodyStart <= 0) {
        return lines.map { l ->
            DecompLine(l.rendered(spell), l.address(), braces = l.placed(spell).braces())
        }
    }
    val (declLines, prefix) = lines.subList(0, bodyStart).partition { it.isDeclaration() }
    val signature = prefix.rendered(spell)
    val head = (
        listOf(signature) +
            groupDecls(declLines.filterNot { it.declaresForeign(func, source) }, spell)
        )
        .filter { it.isNotEmpty() }
        .joinToString(" ")
    // Rejoin the lines Ghidra wrapped one logical line onto: a continuation sits at the same block
    // depth as the line it continues but is indented deeper (a nested statement goes a block deeper; a
    // sibling stays at the same indent). Merging here keeps each logical line on one address, so it
    // lands on one row later. Indent is the head line's own nesting level; braces stay their own lines.
    val body = lines.subList(bodyStart, lines.size).fold(mutableListOf<MutableList<ClangLine>>()) { acc, line ->
        val head = acc.lastOrNull()?.first()
        val continues = head != null &&
            ((line.indent > head.indent && line.blockDepth() == head.blockDepth()) || line.isTrailingPunctuation())
        if (continues) acc.last() += line else acc += mutableListOf(line)
        acc
    }
    // Row 0 is the head, so a body group's row is its index plus one. Needed before the rows exist:
    // a branch group's extent is a pair of row numbers, and the tokens name lines, not rows.
    val rowOf = body.flatMapIndexed { i, g -> g.map { it to i + 1 } }.toMap()

    val declared = (prefix + declLines)
        .flatMap { it.significant() }
        .filterIsInstance<ClangVariableToken>()
        .map { it.text }
        .toSet()
    // The head is the prefix lines with the declarations folded in, so its structure is the prefix's —
    // a declaration carries no brace, no `this` and no condition. It does carry an `if`: gcc gives a
    // leading one no ClangStatement, so it is not code by the body test and folds in here.
    val headTokens = prefix.placed(spell)
    val (headCondition, headBranches, headCuts) = structure(headTokens, rowOf)
    val headRow = DecompLine(
        head,
        null,
        declares = declared,
        braces = headTokens.braces(),
        ifCondition = headCondition,
        branches = headBranches,
        thisAt = headTokens.thisAt(),
        booleanCuts = headCuts,
        memberCuts = memberCutsOf(headTokens, ghFunction),
        prototype = signature,
    )
    return listOf(headRow) + body.map { row(it, rowOf) }
}

private fun List<Placed>.thisAt() = filter { it.token.isThis() }.map { it.at..<it.at + it.token.text.length }

/**
 * The extent of a `this` passed as a call's first argument, comma and all — the offsets that turn
 * `find_slt(this,uVar1)` into `find_slt(uVar1)`.
 *
 * Read off the token stream rather than the characters: a `(this,` can only be found reliably where
 * the `(` is known to open a call's argument list and the `this` is known to be the variable token
 * Ghidra prints for the implicit object parameter, not part of a longer expression like
 * `(this->next)`. A lone `f(this)` loses just the argument.
 */
private fun List<Placed>.thisArguments(): List<IntRange> {
    val significant = significant()
    return significant.indices.mapNotNull { i ->
        val open =
            significant[i].takeIf { it.token.text == "(" && it.token is ClangSyntaxToken } ?: return@mapNotNull null
        if (significant.getOrNull(i - 1)?.token !is ClangFuncNameToken) return@mapNotNull null
        val arg = significant.getOrNull(i + 1)?.takeIf { it.token.isThis() } ?: return@mapNotNull null
        val after = significant.getOrNull(i + 2)?.token?.text
        val end = when (after) {
            "," -> significant[i + 2].at + 1
            ")" -> arg.at + arg.token.text.length
            else -> return@mapNotNull null
        }
        // Take the blank after the comma with it, so the argument list does not render `f( x)`.
        val padded = if (after == "," && significant.getOrNull(i + 3)?.at == end + 1) end + 1 else end
        arg.at..<padded.coerceAtLeast(open.at + 1)
    }
}

/**
 * What a legal C++ member definition of this head must leave out, empty where the function is not a
 * class member.
 *
 * Ghidra prints a member function the way its own model stores one: with a return type on every
 * function, and the `this` pointer as an explicit first parameter. Neither is legal C++ where the
 * definition is qualified — `void bouniaf::bouniaf(bouniaf *this)` draws "constructor cannot have a
 * return type" and "invalid parameter name: 'this' is a keyword" — so a qualified definition drops
 * the explicit parameter, leaving the body's uses of `this` to the implicit one, and a constructor
 * or destructor drops the return type as well.
 *
 * Both are named by *extent*: the return type is a [ClangReturnType] group and the parameter a
 * [ClangVariableDecl] one, so what goes is exactly what Ghidra put there, wherever in the list it
 * sits and however its type is spelled. Finding the parameter list by its parentheses and the `this`
 * inside it by a regex left every `vector<Exclusion*,…> *this` in place — the pattern could not
 * carry a `*` inside the type — and would have mis-cut a parameter that was a function pointer.
 *
 * Only when qualified: dropping the parameter from a free function would leave its body referring to
 * a `this` that no longer exists.
 */
private fun memberCutsOf(tokens: List<Placed>, function: Function?): List<IntRange> {
    val owner = function?.parentNamespace?.takeIf { !it.isGlobal } ?: return emptyList()
    return buildList {
        tokens.groupOf(ClangVariableDecl::class.java) { it.token.isThis() }
            ?.let { add(tokens.extent(it, ",")) }
        // A constructor and a destructor are named for their class; nothing else may drop its return
        // type. For a template it is the *template's* name: `DynArray<char,10ul>`'s ctor is `DynArray`.
        val cls = owner.name.substringBefore('<')
        if (function.name == cls || function.name == "~$cls") {
            tokens.groupOf(ClangReturnType::class.java) { true }?.let { add(tokens.extent(it, null)) }
        }
    }
}

/** The nearest [cls] ancestor of the first token matching [of], or null when none does. */
private fun <T : ClangNode> List<Placed>.groupOf(cls: Class<T>, of: (Placed) -> Boolean) =
    firstOrNull { of(it) && it.token.ancestor(cls) != null }?.token?.ancestor(cls)

/**
 * The offsets [group]'s tokens occupy in the row, extended over one following [separator] and the
 * blanks around it — so cutting the range leaves neither a doubled space nor a dangling comma.
 */
private fun List<Placed>.extent(group: ClangNode, separator: String?): IntRange {
    val own = indices.filter { this[it].token.isUnder(group) }
    val next = (own.last() + 1..<size).firstOrNull { this[it].token.isSignificant }
    // The separator goes with the group: the one after it, or — where the group ends its list, as
    // `this` does for a member whose other parameters precede it — the one before instead.
    val takesNext = separator != null && next != null && this[next].token.text == separator
    val start = when {
        separator == null || takesNext -> own.first()
        else -> (own.first() - 1 downTo 0).firstOrNull { this[it].token.isSignificant }
            ?.takeIf { this[it].token.text == separator } ?: own.first()
    }
    var end = if (takesNext) next + 1 else own.last() + 1
    while (end < size && !this[end].token.isSignificant) end++
    val last = this[own.last()]
    return this[start].at..<(getOrNull(end)?.at ?: (last.at + last.token.text.length))
}

private fun ClangToken.isUnder(group: ClangNode): Boolean =
    generateSequence(Parent()) { it.Parent() }.any { it === group }

/**
 * Group same-typed declaration lines into one statement each. The type is the line's
 * [ClangTypeToken] (Ghidra emits it as one token — the base type, without the `*`/`[N]`
 * declarator), the declarator the tokens after it up to the terminator; types keep first-appearance order.
 */
private fun groupDecls(declLines: List<ClangLine>, spell: Spelling): List<String> = declLines
    .mapNotNull { line ->
        val toks = line.significant()
        val typeIdx = toks.indexOfFirst { it is ClangTypeToken }
        if (typeIdx < 0) return@mapNotNull null
        val declarator = toks.subList(typeIdx + 1, toks.size).dropLast(1).joinToString("") { spell(it) }
        spell(toks[typeIdx]) to declarator
    }
    .groupBy({ it.first }, { it.second })
    .map { (type, declarators) -> "$type ${declarators.joinToString(",")};" }
