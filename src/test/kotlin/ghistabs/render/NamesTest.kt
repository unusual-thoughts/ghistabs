package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * A name read off real source becomes half of a pseudo-name, so what it loses on the way is what a
 * reader has to guess back. Every reserved libstdc++ name opens with `__`.
 */
class NamesTest {
    @Test
    fun `underscores survive, and only illegal characters are replaced`() {
        assertEquals("__destroy_aux", "__destroy_aux".asIdentifier())
        assertEquals("dtor_vector", "~vector".asIdentifier())
        assertEquals("operator_", "operator=".asIdentifier())
        assertEquals("vector__Tp__Alloc__M_insert_aux", "vector<_Tp, _Alloc>::_M_insert_aux".asIdentifier())
    }

    /** The filename half keeps collapsing runs — `stl_vector.h` is one `_` at the dot, not two. */
    @Test
    fun `the file stem still collapses`() {
        assertEquals("stl_vector_h", "stl_vector.h".sanitizeIdentifier())
    }
}
