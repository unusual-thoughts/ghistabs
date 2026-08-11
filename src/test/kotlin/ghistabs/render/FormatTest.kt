package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** Pins [commentFor]: the comment each [NoteShape] spells, and the padding of the line reference. */
class FormatTest {
    @Test
    fun `each shape has its own comment`() {
        assertEquals("// L  17 @ 0x1000: mov", commentFor(17, NoteShape.SLINE, "0x1000: mov"))
        assertEquals("/* L  17 — opens Foo */", commentFor(17, NoteShape.DELIMITER, "opens Foo"))
        assertEquals("// ⇐ L 42", commentFor(17, NoteShape.PROVENANCE, "L 42"))
    }

    @Test
    fun `a declaration tag carries the role and pads the line ref`() {
        assertEquals("// L   1", commentFor(1, NoteShape.DECLARATION, ""))
        assertEquals("// L  17 (param)", commentFor(17, NoteShape.DECLARATION, "(param)"))
    }

    @Test
    fun `every owner maps to a shape, and the declaration-ish ones share it`() {
        assertEquals(NoteShape.PROVENANCE, Owner.FUNCTION_BODY.noteShape)
        assertEquals(NoteShape.PROVENANCE, Owner.INLINED_BODY.noteShape)
        assertEquals(NoteShape.DELIMITER, Owner.FUNC_DELIM.noteShape)
        assertEquals(
            listOf(Owner.GLOBAL, Owner.LOCAL, Owner.TYPEDEF, Owner.TYPE_BODY, Owner.INCLUDE).map {
                NoteShape.DECLARATION
            },
            listOf(Owner.GLOBAL, Owner.LOCAL, Owner.TYPEDEF, Owner.TYPE_BODY, Owner.INCLUDE).map { it.noteShape },
        )
    }
}
