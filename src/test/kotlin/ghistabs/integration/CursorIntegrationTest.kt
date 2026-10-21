package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.cursorAt
import ghistabs.nextPointer
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** A cursor that can't move past a word doesn't hand it out, so a read loop moves on or stops at the end of space. */
@Tag("integration")
class CursorIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".top", "0xfffffff8", 8) // the last two words of the address space
        builder.setBytes("0xfffffff8", "00 10 40 00 00 20 40 00")
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun `the last word of the address space ends the read rather than repeating`() {
        val cursor = program.cursorAt(builder.addr("0xfffffff8"))
        cursor.nextPointer() mustBe builder.addr("0x401000")
        cursor.address mustBe builder.addr("0xfffffffc")
        cursor.nextPointer() mustBe null
        cursor.address mustBe builder.addr("0xfffffffc")
    }
}
