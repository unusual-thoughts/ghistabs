package ghistabs.render

import ghidra.app.decompiler.ClangBreak
import ghidra.app.decompiler.ClangCommentToken
import ghidra.app.decompiler.ClangFuncProto
import ghidra.app.decompiler.ClangLine
import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.ClangStatement
import ghidra.app.decompiler.ClangToken
import ghidra.app.decompiler.ClangTypeToken
import ghidra.app.decompiler.DecompileResults
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
fun DecompileResults.compressedDecompLines(): List<DecompLine> {
    val lines = DecompilerUtils.toLines(cCodeMarkup)
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
