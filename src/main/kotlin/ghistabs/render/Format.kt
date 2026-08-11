package ghistabs.render

// Pure text formatting: how skeleton output is spelled, with no Ghidra, no harvest
// types, and no decisions. Every provenance comment restates the fragment's line — a
// render-time decoration derived from position — so it's formatted here from the line
// index, not baked into the fragment by the emit passes.

// "L  17" — the source-line reference stamped on every tag.
private fun lineRef(line: Int) = "L" + line.toString().padStart(4)

/**
 * How a row's [note] is spelled once it reaches the page.
 *
 * Four cases, because four is how many the rendered text actually distinguishes. The `FragmentKind`
 * this replaces had eight, five of which ([DECLARATION]'s) produced the same comment — a distinction
 * that existed only to be mapped back from [Owner], and had to be kept in step with it for no gain.
 */
enum class NoteShape {
    /** An N_SLINE address annotation: which instructions the line compiled to. */
    SLINE,

    /** A function's opening or closing brace, naming what it delimits. */
    DELIMITER,

    /**
     * Which source line a decompiled statement's instructions came from. Reaches [commentFor] only
     * for a row with no code of its own; where there is code the marker goes in *front* of it, which
     * [TargetLine.render] does because collapsing repeats needs the whole row.
     */
    PROVENANCE,

    /** A declaration's provenance tag, carrying its role — the shape everything else takes. */
    DECLARATION,
}

/**
 * The trailing comment for a fragment carrying [note] at [line], shaped by [shape]. A [DECLARATION]
 * tag's [note] is the role: empty for a typedef or type body, "(param)" and the like for a decl.
 */
fun commentFor(line: Int, shape: NoteShape, note: String) = when (shape) {
    NoteShape.SLINE -> "// ${lineRef(line)} @ $note"
    NoteShape.DELIMITER -> "/* ${lineRef(line)} — $note */"
    NoteShape.PROVENANCE -> "// ⇐ $note"
    NoteShape.DECLARATION -> "// ${lineRef(line)}" + if (note.isEmpty()) "" else " $note"
}
