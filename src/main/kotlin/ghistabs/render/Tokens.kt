package ghistabs.render

import ghidra.app.decompiler.*
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.program.model.address.Address
import ghistabs.entrypoints.Correction
import ghistabs.harvest.BlockScope
import ghistabs.harvest.Func
import ghistabs.harvest.GhidraSourceFile

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
fun <T : ClangNode> ClangToken.ancestor(cls: Class<T>): T? {
    var node: ClangNode? = Parent()
    while (node != null) {
        if (cls.isInstance(node)) return cls.cast(node)
        node = node.Parent()
    }
    return null
}

private fun ClangToken.inside(cls: Class<out ClangNode>) = ancestor(cls) != null

fun ClangNode.children() = (0..<numChildren()).map { Child(it) }

private fun ClangNode.leaves() = mutableListOf<ClangNode>().also { flatten(it) }.filterIsInstance<ClangToken>()

// A `beginBlock`/`endBlock` group, which `printc.cc` emits as a plain group — `ClangStatement`,
// `ClangVariableDecl`, `ClangReturnType` and `ClangFuncProto` are distinct subclasses.
fun ClangNode.asBlock() = (this as? ClangTokenGroup)?.takeIf { it::class == ClangTokenGroup::class }

fun ClangNode?.spells(text: String) = (this as? ClangToken)?.text == text

// Block-nesting level: the shallowest token's count of enclosing block groups. Equal for a wrapped
// line's continuations and their header; one deeper for a nested statement.
fun ClangLine.blockDepth() = significant().minOfOrNull { tok ->
    generateSequence(tok.Parent()) { it.Parent() }.count { it.asBlock() != null }
} ?: 0

// The x86 calling-convention keywords Ghidra prints in a prototype; noise in a source skeleton.
// Derived spellings included: StructReturnAnalyzer installs `__thiscall_memret`/`__cdecl_regret` as
// ordinary prototype models, so Ghidra prints them here exactly like a stock convention.
private val CALLING_CONVENTIONS = setOf("__thiscall", "__cdecl", "__stdcall", "__fastcall", "__vectorcall")
    .let { base -> base + base.flatMap { c -> Correction.entries.map { c + it.suffix } } }

// Tokens carrying text, minus line breaks and the calling-convention keyword (with the one blank
// that trails it, so `ushort __thiscall Foo::m` reads `ushort Foo::m`, not `ushort  Foo::m`).
fun ClangLine.content(): List<ClangToken> = buildList {
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

val ClangToken.isSignificant get() = text.isNotBlank()
fun ClangLine.significant() = content().filter { it.isSignificant }
private fun ClangNode.significantLeaves() = leaves().filter { it.isSignificant }
fun List<Placed>.significant() = filter { it.token.isSignificant }

/**
 * Each of this line's content tokens with the offset its spelling takes in the line's *trimmed*
 * render — the form a row carries. The lead is whatever the trim takes off the front, which is the
 * indent plus any leading spacer token.
 */
fun ClangLine.placed(spell: Spelling): List<Placed> {
    val full = indentString + content().joinToString("") { spell(it) }
    var at = indentString.length - (full.length - full.trimStart().length)
    return content().map { t -> Placed(t, at).also { at += spell(t).length } }
}

fun ClangLine.rendered(spell: Spelling) = (indentString + content().joinToString("") { spell(it) }).trimEnd()

/**
 * What separates a rejoined fragment from the one [previous] left off at: one space, standing in for
 * the one the break replaced — except between a function's name and its own parameter list, which is
 * one construct with nothing between the two, and which the pretty-printer breaks at because
 * `openParen` opens a group. Without the exception a signature Ghidra wrapped after the name comes
 * back as `name (…)`; with it applied to every paren, `a ||(b)` and `f(x,(y))` lose theirs.
 */
fun ClangLine.rejoin(previous: ClangLine) = if (previous.significant().lastOrNull() is ClangFuncNameToken &&
    significant().firstOrNull().let { it is ClangSyntaxToken && it.open >= 0 }
) {
    ""
} else {
    " "
}

// A brace is a ClangSyntaxToken, so a `{` reaching the text from a string literal or a comment — which
// arrive as other token kinds — is not one, the way a character count would have it.
fun ClangToken.isBrace() = this is ClangSyntaxToken && DecompilerUtils.isBrace(this)

// A group holding its own delimiters: the pending brace was printed inside it, and the nested
// `emitBlockIf` that owns that brace closes it inside too.
fun ClangNode.wrapsItsOwnBraces() = significantLeaves()
    .let { it.firstOrNull().spells("{") && it.lastOrNull().spells("}") }

// The rows the group's tokens landed on — minus its own delimiters where it carries them, those
// sitting on the separator and closing rows, which belong to neither branch.
fun ClangNode.rows(rowOf: Map<ClangLine, Int>, unwrap: Boolean = false): IntRange? {
    val inner = significantLeaves().let { if (unwrap) it.drop(1).dropLast(1) else it }
    return inner.mapNotNull { rowOf[it.lineParent] }.ifEmpty { null }?.let { it.min()..it.max() }
}

fun ClangLine.addresses(): List<Address> = content().mapNotNull { it.minAddress }
fun ClangLine.address(): Address? = addresses().minOrNull()
fun ClangLine.stackOffsets(): List<Long> = content()
    .filterIsInstance<ClangVariableToken>()
    .mapNotNull { it.varnode?.address?.takeIf { a -> a.isStackAddress }?.offset }

// A line's role, read from its tokens' kinds and tree position — never from the rendered characters.
fun ClangLine.isComment() = significant().let { it.isNotEmpty() && it.all { t -> t is ClangCommentToken } }
fun ClangLine.isCode() = content().any { it.inside(ClangStatement::class.java) }
private fun ClangLine.isSignature() = content().any { it.inside(ClangFuncProto::class.java) }

// A local-variable declaration line — a `ClangVariableDecl` group, not merely a line carrying a
// type token (a `(uint)` cast in `else if ((uint)i < 4)` would false-positive that). The signature's
// params are also ClangVariableDecls, so exclude it.
fun ClangLine.isDeclaration() = !isSignature() && content().any { it.inside(ClangVariableDecl::class.java) }

// A wrap fragment that is only trailing punctuation (`;`/`)`/`.`/`,`) — Ghidra broke it off the end
// of a long statement with no extra indent, so it carries no address and the depth-based rejoin can't
// see it. Never a statement of its own, so it rejoins its predecessor unconditionally. Braces aren't
// in the set, so a `}` still keeps its own row.
private val TRAILING_PUNCTUATION = setOf(";", ")", ".", ",", "->")
fun ClangLine.isTrailingPunctuation() =
    significant().let { toks -> toks.isNotEmpty() && toks.all { it.text in TRAILING_PUNCTUATION } }

// A declaration of a local gcc attributed to a header: its lexical block was inlined from one, so it
// is declared in that header's own render and has no business in this file's. Ghidra dedups colliding
// names with a `_<n>` suffix, so the base name is what matches; a name shared with a this-file local
// stays, the two being indistinguishable here. The suffix is Ghidra's spelling of one identifier, not
// a shape read out of a rendered row.
private val DEDUP_SUFFIX = Regex("_\\d+$")

fun ClangLine.declaresForeign(func: Func, source: GhidraSourceFile): Boolean {
    val name = significant().lastOrNull { it is ClangVariableToken }?.text?.replace(DEDUP_SUFFIX, "") ?: return false
    val matching = func.locals.filter { it.body.name == name }
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
fun ClangToken.isThis() = this is ClangVariableToken && text == THIS
