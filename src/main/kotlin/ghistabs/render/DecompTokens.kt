package ghistabs.render

import ghidra.app.decompiler.*
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.program.model.address.Address

/** A rendered decompiler line and the lowest instruction address its tokens map to (null for the folded header / a structural line). */
data class DecompLine(val text: String, val address: Address?)

/** True if an ancestor group of this token is a [cls] (e.g. ClangStatement, ClangFuncProto). */
private fun ClangToken.inside(cls: Class<out ClangNode>): Boolean {
    var node: ClangNode? = Parent()
    while (node != null) {
        if (cls.isInstance(node)) return true
        node = node.Parent()
    }
    return false
}

private fun ClangLine.content() = allTokens.filterNot { it is ClangBreak }
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
private fun ClangLine.isDeclaration() = !isCode() && !isSignature() && significant().any { it is ClangTypeToken }

/**
 * Decompiler output with the leading declaration block folded onto the signature line and
 * same-typed locals grouped (`string *a; string *b;` → `string *a,*b;`), so statements start at
 * the top of the span instead of one-decl-per-line pushing them down. Every line's role and each
 * declaration's type are read from the clang token stream — comment banners by ClangCommentToken,
 * statements by ClangStatement ancestry, the signature by ClangFuncProto, declarations by a
 * ClangTypeToken outside both — so nothing is guessed from the rendered characters.
 */
fun DecompileResults.compressedDecompLines(elideSjlj: Boolean = false): List<DecompLine> {
    // exception in box2d, cCodeMarkup was null for some function. should log.
    val raw = DecompilerUtils.toLines(cCodeMarkup ?: return listOf())
    val victims = if (elideSjlj) sjljScaffolding(raw) else emptySet()
    val lines = raw
        .filterNot { it in victims }
        .dropWhile { it.isComment() || it.significant().isEmpty() }
    val bodyStart = lines.indexOfFirst { it.isCode() }
    if (bodyStart <= 0) return lines.map { DecompLine(it.rendered(), it.address()) }
    val (declLines, prefix) = lines.subList(0, bodyStart).partition { it.isDeclaration() }
    val head = (prefix.map { it.rendered().trim() } + groupDecls(declLines))
        .filter { it.isNotEmpty() }
        .joinToString(" ")
    return listOf(DecompLine(head, null)) +
        lines.subList(bodyStart, lines.size).map { DecompLine(it.rendered(), it.address()) }
}

/**
 * Group same-typed declaration lines into one statement each. The type is the line's
 * [ClangTypeToken] (Ghidra emits it as one token — the base type, without the `*`/`[N]`
 * declarator), the declarator the tokens after it up to the terminator; types keep first-
 * appearance order.
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
