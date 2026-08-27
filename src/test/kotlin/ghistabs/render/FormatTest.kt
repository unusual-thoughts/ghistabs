package ghistabs.render

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** Pins [Fragment.commentAt]: the comment each [NoteShape] spells, and the padding of the line reference. */
class FormatTest {
    private fun note(note: String?, shape: NoteShape) = Fragment(note = note, shape = shape)

    @Test
    fun `each shape has its own comment`() {
        note("0x1000: mov", NoteShape.SLINE).commentAt(17) mustBe "// L  17 @ 0x1000: mov"
        note("opens Foo", NoteShape.DELIMITER).commentAt(17) mustBe "/* L  17 — opens Foo */"
        note("L 42", NoteShape.PROVENANCE).commentAt(17) mustBe "// ⇐ L 42"
    }

    @Test
    fun `a declaration tag carries the role and pads the line ref`() {
        note("", NoteShape.DECLARATION).commentAt(1) mustBe "// L   1"
        note("(param)", NoteShape.DECLARATION).commentAt(17) mustBe "// L  17 (param)"
    }

    /** A pure-code fragment has no payload, and a comment shape it never uses spells nothing. */
    @Test
    fun `no note is no comment, whatever the shape`() {
        NoteShape.entries.map { note(null, it).commentAt(17) } mustBe NoteShape.entries.map { null }
    }

    @Test
    fun `every owner maps to a shape, and the declaration-ish ones share it`() {
        Owner.FUNCTION_BODY.noteShape mustBe NoteShape.PROVENANCE
        Owner.INLINED_BODY.noteShape mustBe NoteShape.PROVENANCE
        Owner.FUNC_DELIM.noteShape mustBe NoteShape.DELIMITER
        listOf(Owner.GLOBAL, Owner.LOCAL, Owner.TYPEDEF, Owner.TYPE_BODY, Owner.INCLUDE).map { it.noteShape } mustBe
            listOf(Owner.GLOBAL, Owner.LOCAL, Owner.TYPEDEF, Owner.TYPE_BODY, Owner.INCLUDE).map {
                NoteShape.DECLARATION
            }
    }
}
