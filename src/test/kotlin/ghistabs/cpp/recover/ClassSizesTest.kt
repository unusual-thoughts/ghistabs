package ghistabs.cpp.recover

import ghistabs.cpp.TestClass
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class ClassSizesTest {
    private val a = TestClass("A")
    private val b = TestClass("B")
    private val d = TestClass("D")
    private val s = TestClass("S")

    @Test
    fun `a class is at least as large as its last vptr and its bases reach`() {
        // class D : B, S with S at 0x58; B and S each a vptr and nothing known past it
        val bounds = sizeBounds(
            bases = mapOf(d to listOf(b to 0L, s to 0x58L)),
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
        val bounds = sizeBounds(
            bases = mapOf(d to listOf(b to 0L, s to 0x58L)),
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
        val bounds = sizeBounds(
            bases = mapOf(d to listOf(b to 0L, s to 8L), b to listOf(a to 0L)),
            vptrs = mapOf(a to 0L, b to 4L),
            allocated = emptyMap(),
            ptrSize = 4,
        )
        bounds.getValue(b) mustBe 8L..8L
        bounds.getValue(a).last mustBe 8
    }
}
