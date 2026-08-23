package ghistabs.render

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * A name read off real source becomes half of a pseudo-name, so what it loses on the way is what a
 * reader has to guess back. Every reserved libstdc++ name opens with `__`.
 */
class NamesTest {
    @Test
    fun `underscores survive, and only illegal characters are replaced`() {
        "__destroy_aux".asIdentifier() mustBe "__destroy_aux"
        "~vector".asIdentifier() mustBe "dtor_vector"
        "operator=".asIdentifier() mustBe "operator_"
        "vector<_Tp, _Alloc>::_M_insert_aux".asIdentifier() mustBe "vector__Tp__Alloc__M_insert_aux"
    }

    /** The filename half keeps collapsing runs — `stl_vector.h` is one `_` at the dot, not two. */
    @Test
    fun `the file stem still collapses`() {
        "stl_vector.h".sanitizeIdentifier() mustBe "stl_vector_h"
    }
}
