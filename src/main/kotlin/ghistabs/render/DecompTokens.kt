package ghistabs.render

import ghidra.app.decompiler.DecompileResults
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.program.model.address.Address

/**
 * One decompiler output line: its text and the lowest instruction address its tokens map to. A
 * declaration, brace or comment line carries no address (its tokens are pure syntax); a statement
 * line does. That address is what tells declarations apart from code and, later, flows each
 * statement onto its N_SLINE source line.
 */
data class DecompLine(val text: String, val address: Address?)

/** The decompiler's clang token stream as [DecompLine]s (text reconstructed from the leaf tokens). */
fun DecompileResults.tokenLines(): List<DecompLine> = DecompilerUtils.toLines(cCodeMarkup).map { line ->
    val text = line.indentString + line.allTokens.joinToString("") { it.text }
    DecompLine(text.trimEnd(), line.allTokens.mapNotNull { it.minAddress }.minOrNull())
}

/**
 * Decompiler output with the leading declaration block folded onto the signature line. gcc-style
 * locals (`ushort value; uVar1; undefined2 in_stack_…;`) otherwise take one skeleton line each,
 * eating vertical room and pushing every statement off its source line. The decompiler's banner
 * comment is stripped and a lone opening brace folded onto the signature, as before — but the
 * declaration run is now found by address (a decl line has none), not by text shape.
 */
fun DecompileResults.compressedDecompLines(): List<String> {
    val lines = tokenLines().dropWhile {
        it.text.isBlank() || (it.text.trimStart().startsWith("/*") && it.text.trimEnd().endsWith("*/"))
    }
    // Fold the signature, opening brace and the gcc-style local declaration block that follows it
    // (address-less lines) onto one head line, so statements start at the top of the span instead
    // of one-decl-per-line pushing them all down. The brace anchors this regardless of whether the
    // signature itself carries an address.
    val brace = lines.indexOfFirst { '{' in it.text }
    if (brace < 0) return lines.map { it.text }
    var end = brace + 1
    while (end < lines.size && lines[end].address == null && lines[end].text.isNotBlank() && '}' !in lines[end].text) {
        end++
    }
    val sig = lines.subList(0, brace + 1).joinToString(" ") { it.text.trim() }
    val declTexts = lines.subList(brace + 1, end).map { it.text.trim().trimEnd(';').trim() }.filter { it.isNotEmpty() }
    val head = (listOf(sig) + groupDecls(declTexts)).joinToString(" ")
    return listOf(head) + lines.subList(end, lines.size).map { it.text }
}

/**
 * Collapse same-typed local declarations into one statement each (`string *a; string *b;` →
 * `string *a,*b;`). Ghidra emits decl types as a single space-free token (`undefined4`,
 * `vector<std::string,…>`), so the type is the text up to the first space and the declarator
 * (with its `*`s / `[N]`) the rest; types group in first-appearance order. A decl with no
 * declarator (no space) is emitted verbatim.
 */
private fun groupDecls(decls: List<String>): List<String> {
    val (typed, bare) = decls.partition { ' ' in it }
    val grouped = typed
        .groupBy({ it.substringBefore(' ') }, { it.substringAfter(' ') })
        .map { (type, declarators) -> "$type ${declarators.joinToString(",")};" }
    return grouped + bare.map { "$it;" }
}
