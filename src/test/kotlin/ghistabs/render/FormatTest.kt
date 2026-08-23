package ghistabs.render

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** Pins [commentFor]: the comment each [NoteShape] spells, and the padding of the line reference. */
class FormatTest {
    @Test
    fun `each shape has its own comment`() {
        commentFor(17, NoteShape.SLINE, "0x1000: mov") mustBe "// L  17 @ 0x1000: mov"
        commentFor(17, NoteShape.DELIMITER, "opens Foo") mustBe "/* L  17 — opens Foo */"
        commentFor(17, NoteShape.PROVENANCE, "L 42") mustBe "// ⇐ L 42"
    }

    @Test
    fun `a declaration tag carries the role and pads the line ref`() {
        commentFor(1, NoteShape.DECLARATION, "") mustBe "// L   1"
        commentFor(17, NoteShape.DECLARATION, "(param)") mustBe "// L  17 (param)"
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
