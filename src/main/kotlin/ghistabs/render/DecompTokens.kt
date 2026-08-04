package ghistabs.render

import ghidra.app.decompiler.*
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.program.model.address.Address
import ghistabs.Correction

/**
 * A rendered decompiler line, the lowest instruction address its tokens map to (null for the folded
 * header / a structural line), and its indent [depth] — the line's own structural nesting level from
 * Ghidra (0 = the signature/close-brace column), used verbatim as the leading space count.
 */
data class DecompLine(val text: String, val address: Address?, val depth: Int = 0)

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

// Block-nesting level: the shallowest token's count of enclosing plain `ClangTokenGroup`s (the block
// groups — `ClangStatement`/`ClangVariableDecl`/… are distinct subclasses and don't count). Equal for
// a wrapped line's continuations and their header; one deeper for a nested statement.
private fun ClangLine.blockDepth() = significant().minOfOrNull { tok ->
    generateSequence(tok.Parent()) { it.Parent() }.count { it::class == ClangTokenGroup::class }
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
            dropTrailingBlank && t.text.isBlank() -> dropTrailingBlank = false
            else -> {
                add(t)
                dropTrailingBlank = false
            }
        }
    }
}

private fun ClangLine.significant() = content().filter { it.text.isNotBlank() }

private fun ClangLine.rendered() = (indentString + content().joinToString("") { it.text }).trimEnd()
private fun ClangLine.address(): Address? = content().mapNotNull { it.minAddress }.minOrNull()
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

/**
 * Decompiler output with the leading declaration block folded onto the signature line and
 * same-typed locals grouped (`string *a; string *b;` → `string *a,*b;`), so statements start at
 * the top of the span instead of one-decl-per-line pushing them down. Every line's role and each
 * declaration's type are read from the clang token stream — comment banners by ClangCommentToken,
 * statements by ClangStatement ancestry, the signature by ClangFuncProto, declarations by
 * ClangVariableDecl ancestry, K&R nesting by the line's own `indent` — so nothing is guessed from
 * the rendered characters.
 */
fun DecompileResults.compressedDecompLines(elideSjlj: Boolean = false): List<DecompLine> {
    // exception in box2d, cCodeMarkup was null for some function. should log.
    val raw = DecompilerUtils.toLines(cCodeMarkup ?: return listOf())
    val victims = if (elideSjlj) sjljScaffolding(raw) else emptySet()
    // Drop Ghidra's blank lines outright — we place with our own spacing, and a stray blank
    // otherwise surfaces as a bare `// ⇐ L NN` tag when a run breaks into the gap below the span.
    val lines = raw
        .filterNot { it in victims || it.significant().isEmpty() }
        .dropWhile { it.isComment() }
    val bodyStart = lines.indexOfFirst { it.isCode() }
    if (bodyStart <= 0) return lines.map { DecompLine(it.rendered(), it.address()) }
    val (declLines, prefix) = lines.subList(0, bodyStart).partition { it.isDeclaration() }
    val head = (prefix.map { it.rendered().trim() } + groupDecls(declLines))
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
    return listOf(DecompLine(head, null)) +
        body.map { g ->
            DecompLine(g.joinToString(" ") { it.rendered().trim() }, g.first().address(), g.first().indent)
        }
}

/**
 * Group same-typed declaration lines into one statement each. The type is the line's
 * [ClangTypeToken] (Ghidra emits it as one token — the base type, without the `*`/`[N]`
 * declarator), the declarator the tokens after it up to the terminator; types keep first-appearance order.
 */
private fun groupDecls(declLines: List<ClangLine>): List<String> = declLines
    .mapNotNull { line ->
        val toks = line.significant()
        val typeIdx = toks.indexOfFirst { it is ClangTypeToken }
        if (typeIdx < 0) return@mapNotNull null
        val declarator = toks.subList(typeIdx + 1, toks.size).dropLast(1).joinToString("") { it.text }
        toks[typeIdx].text to declarator
    }
    .groupBy({ it.first }, { it.second })
    .map { (type, declarators) -> "$type ${declarators.joinToString(",")};" }
