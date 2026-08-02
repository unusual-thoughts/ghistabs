package ghistabs

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.CommentType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.StabSectionOverlay
import ghistabs.parse.STAB_RECORD_SIZE
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Real Ghidra headless test for [StabSectionOverlay]: decoded StabRecord structs land on every
 * `.stab` entry, `n_strx` references `.stabstr`, and address-bearing records reference code/data.
 */
@Tag("integration")
class StabSectionOverlayIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    private val stabBase = 0x401000L
    private val stabstrBase = 0x402000L
    private val funcAddr = 0x400100L

    // .stabstr: leading NUL (empty), then "main", then "x:t(0,1)".
    private val stabstr = byteArrayOf(0) + "main".toByteArray() + byteArrayOf(0) +
        "x:t(0,1)".toByteArray() + byteArrayOf(0)

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".text", "0x400000", 512)
        builder.createMemory(".stab", "0x401000", 3 * STAB_RECORD_SIZE)
        builder.createMemory(".stabstr", "0x402000", stabstr.size)

        val stab = record(0, 0x00, 0, 0, stabstr.size.toLong()) + // N_UNDF, value = stabstr size
            record(1, 0x24, 0, 0, funcAddr) + // N_FUN "main" @ funcAddr
            record(6, 0x80, 0, 5, 0) // N_LSYM "x:t(0,1)"
        builder.setBytes("0x401000", stab)
        builder.setBytes("0x402000", stabstr)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun record(strx: Int, type: Int, other: Int, desc: Int, value: Long) =
        ByteBuffer.allocate(STAB_RECORD_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(strx).put(type.toByte()).put(other.toByte()).putShort(desc.toShort()).putInt(value.toInt())
            .array()

    private fun addr(off: Long): Address = builder.program.addressFactory.defaultAddressSpace.getAddress(off)

    @Test
    fun overlaysDecodedStructsRefsAndComments() {
        val program = builder.program
        val applied = StabSectionOverlay(program.defaultContext()).apply()
        assertEquals(3, applied, "all three physical records overlaid")

        // Every record is a StabRecord struct.
        for (i in 0 until 3) {
            val data = program.listing.getDataAt(addr(stabBase + i * STAB_RECORD_SIZE))
            assertNotNull(data, "data at record $i")
            assertTrue(data!!.dataType is Structure && data.dataType.name == "StabRecord", "record $i is StabRecord")
        }

        val funRec = stabBase + STAB_RECORD_SIZE

        // N_FUN: n_strx (field 0) → "main" at .stabstr+1; n_value (offset 8) → the function.
        val strxRefs = program.referenceManager.getReferencesFrom(addr(funRec))
        assertEquals(stabstrBase + 1, strxRefs.single().toAddress.offset, "n_strx → main string")
        val valueRefs = program.referenceManager.getReferencesFrom(addr(funRec + 8))
        assertEquals(funcAddr, valueRefs.single().toAddress.offset, "n_value → function")

        // EOL comment decodes type + name.
        assertEquals("N_FUN \"main\"", program.listing.getComment(CommentType.EOL, addr(funRec)))

        // The referenced .stabstr strings are defined.
        val mainStr = program.listing.getDataAt(addr(stabstrBase + 1))
        assertTrue(mainStr?.value == "main", "main string defined in .stabstr")
    }

    @Test
    fun idempotentReapply() {
        val program = builder.program
        StabSectionOverlay(program.defaultContext()).apply()
        val again = StabSectionOverlay(program.defaultContext()).apply()
        assertEquals(3, again, "re-apply reuses the StabRecord datatype and re-overlays cleanly")
        assertEquals(1, program.dataTypeManager.allStructures.asSequence().count { it.name == "StabRecord" })
    }
}
