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
    // Decomp keeps the decompiler's own statement order; the tag says which source line the
    // statement's instructions actually came from ([note]), since the grid position doesn't.
    FragmentKind.DECOMP -> "// ⇐ $note"
    else -> {
        val role = if (note.isEmpty()) "" else " $note"
        val staleMark = if (stale) "${if (note.isEmpty()) "" else ";"} stale N_SOL?" else ""
        "// ${lineRef(line)}$role$staleMark"
    }
}
