package ghistabs.render

// Pure text formatting: how skeleton output is spelled, with no Ghidra, no harvest
// types, and no decisions. Every provenance comment restates the fragment's line — a
// render-time decoration derived from position — so it's formatted here from the line
// index, not baked into the fragment by the emit passes.

// "L  17" — the source-line reference stamped on every tag.
private fun lineRef(line: Int) = "L" + line.toString().padStart(4)

/**
 * The trailing comment for a fragment carrying [note] at [line]. The shape is chosen by
 * [kind]: an SLINE address annotation, a function brace delimiter, a displaced-decl
 * stray, or (default) a declaration provenance tag whose [note] is the role — empty for
 * a typedef/type-body, "(param)" etc for a decl — with the stale marker appended.
 */
fun commentFor(line: Int, kind: FragmentKind, note: String, stale: Boolean) = when (kind) {
    FragmentKind.SLINE -> "// ${lineRef(line)} @ $note"
    FragmentKind.FUNC_DELIM -> "/* ${lineRef(line)} — $note */"
    FragmentKind.STRAY -> "// stray: $note"
    else -> {
        val role = if (note.isEmpty()) "" else " $note"
        val staleMark = if (stale) "${if (note.isEmpty()) "" else ";"} stale N_SOL?" else ""
        "// ${lineRef(line)}$role$staleMark"
    }
}

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
