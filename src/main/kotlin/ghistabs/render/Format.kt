package ghistabs.render

// Pure text formatting: how skeleton output is spelled, with no Ghidra, no harvest
// types, and no decisions. Callers decide what to emit and on which line; these turn
// the pieces into the exact strings that appear. Isolated here so the output format
// can change without touching render logic.

// "L  17" — the source-line reference stamped on every tag.
private fun lineRef(line: Int) = "L" + line.toString().padStart(4)

// Trailing line-comment tag: "// L  17", optionally flagged stale.
fun lineTag(line: Int, stale: Boolean = false) = "// ${lineRef(line)}" + if (stale) " stale N_SOL?" else ""

// A param/local/global decl tag: "// L  17 (param)", stale marker after the role.
fun declTag(line: Int, role: String, stale: Boolean) = "${lineTag(line)} $role" + if (stale) "; stale N_SOL?" else ""

// An N_SLINE address annotation: "// L  17 @ 0x…-0x… : mnemonic".
fun slineComment(line: Int, addrRuns: String, codeUnit: String) =
    "${lineTag(line)} @ $addrRuns" + if (codeUnit.isEmpty()) "" else ": $codeUnit"

// A function brace delimiter: "/* L  17 — opens Foo */" / "… — closes Foo" / "… — Foo".
fun funcDelimComment(line: Int, note: String) = "/* ${lineRef(line)} — $note */"

// A declaration the decompilation displaced off its line: "// stray: <text>".
fun strayComment(text: String) = "// stray: $text"

/** Drop the decomp's leading header/warning comments and fold a lone `{` onto the signature. */
fun cleanDecompLines(cCode: String): List<String> {
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
