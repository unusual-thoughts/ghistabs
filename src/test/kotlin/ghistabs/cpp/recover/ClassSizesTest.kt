package ghistabs.cpp.recover

import ghistabs.cpp.Access
import ghistabs.cpp.ClassBase
import ghistabs.cpp.TestClass
import ghistabs.cpp.at
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class ClassSizesTest {
    private val a = TestClass("A")
    private val s = TestClass("S")

    @Test
    fun `a class is at least as large as its last vptr and its bases reach`() {
        // class D : B, S with S at 0x58; B and S each a vptr and nothing known past it
        val b = TestClass("B")
        val d = TestClass("D", listOf(b at 0, s at 0x58))
        val bounds = sizeBounds(
            classes = listOf(d, b, s),
            vptrs = mapOf(b to 0L, s to 0L, d to 0x58L),
            allocated = emptyMap(),
            ptrSize = 4,
        )
        bounds.getValue(d) mustBe 0x5cL..Long.MAX_VALUE
        // B ends where S starts
        bounds.getValue(b) mustBe 4L..0x58L
    }

    @Test
    fun `new says a class's size, which bounds its last base`() {
        val b = TestClass("B")
        val d = TestClass("D", listOf(b at 0, s at 0x58))
        val bounds = sizeBounds(
            classes = listOf(d, b, s),
            vptrs = mapOf(s to 0L),
            allocated = mapOf(d to 0x7cL),
            ptrSize = 4,
        )
        bounds.getValue(d) mustBe 0x7cL..0x7cL
        bounds.getValue(s).last mustBe 0x24
    }

    @Test
    fun `bounds that meet are the size`() {
        // B has a vptr and an int, and D's second base starts right after it
        val b = TestClass("B", listOf(a at 0))
        val d = TestClass("D", listOf(b at 0, s at 8))
        val bounds = sizeBounds(
            classes = listOf(d, b, a, s),
            vptrs = mapOf(a to 0L, b to 4L),
            allocated = emptyMap(),
            ptrSize = 4,
        )
        bounds.getValue(b) mustBe 8L..8L
        bounds.getValue(a).last mustBe 8
    }

    @Test
    fun `a virtual base takes no offset in its holder`() {
        val d = TestClass("D", listOf(s at 0, ClassBase(a, true, Access.PUBLIC, null)))
        val bounds = sizeBounds(listOf(d, a, s), mapOf(a to 0L), emptyMap(), ptrSize = 4)
        bounds.getValue(a) mustBe 4L..Long.MAX_VALUE
    }
}
