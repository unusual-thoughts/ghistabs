package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Data
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.decode
import ghistabs.read
import ghistabs.test.mustBe
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@Tag("integration")
class DataFormatIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    enum class Kind { NONE, PLAIN, VIRTUAL }

    @Serializable
    data class Inner(val lo: Short, val hi: Long, val isVirtual: Boolean, val access: Int)

    @Serializable
    data class Outer(
        val offset: Int,
        @Contextual val target: Address,
        val inner: Inner,
        val kind: Kind,
        val words: List<UShort>,
        val pairs: List<Inner>,
        val missing: Int? = null,
        val defaulted: String = "d",
    )

    @Serializable
    data class Raw(@Contextual val inner: Data)

    @Serializable
    data class Wrong(val nope: Int)

    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    private val inner by lazy {
        StructureDataType("Inner", 0).apply {
            add(ShortDataType.dataType, "lo", null)
            add(UnsignedIntegerDataType.dataType, "hi", null)
            addBitField(ByteDataType.dataType, 1, "isVirtual", null)
            addBitField(ByteDataType.dataType, 2, "access", null)
            setToDefaultPacking()
        }
    }

    private val outer by lazy {
        val kind = EnumDataType("Kind", 1).apply {
            add("NONE", 0)
            add("VIRTUAL", 7)
            add("PLAIN", 9)
        }
        StructureDataType("Outer", 0).apply {
            add(IntegerDataType.dataType, "offset", null)
            add(PointerDataType(VoidDataType.dataType, 4), "target", null)
            add(TypedefDataType("Inner_t", inner), "inner", null)
            add(kind, "kind", null)
            add(ArrayDataType(UnsignedShortDataType.dataType, 3, 2), "words", null)
            add(ArrayDataType(inner, 2, inner.length), "pairs", null)
        }
    }

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".data", "0x401000", 0x100)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun laid(dt: DataType): Data {
        builder.applyDataType("0x401000", dt)
        return program.listing.getDataAt(builder.addr(0x401000))
    }

    private fun inner(lo: Int, hi: String, bits: Int) =
        "%02x %02x 00 00 %s %02x 00 00 00".format(lo and 0xff, lo shr 8 and 0xff, hi, bits)

    private fun lay() {
        builder.setBytes(
            "0x401000",
            listOf(
                "fc ff ff ff",
                "10 20 40 00",
                inner(0xfffe, "ff ff ff ff", 0b101),
                "09",
                "01 00 02 00 ff ff",
                inner(1, "02 00 00 00", 0),
                inner(3, "04 00 00 00", 0b111),
            ).joinToString(" "),
        )
    }

    @Test
    fun `a structure reads into its class, nested composites, arrays, bitfields and enums by name`() {
        lay()
        program.read<Outer>(builder.addr(0x401000), outer) mustBe Outer(
            offset = -4,
            target = builder.addr(0x402010),
            inner = Inner(-2, 0xffffffffL, isVirtual = true, access = 2),
            kind = Kind.PLAIN,
            words = listOf<UShort>(1u, 2u, 0xffffu),
            pairs = listOf(Inner(1, 2, isVirtual = false, access = 0), Inner(3, 4, isVirtual = true, access = 3)),
        )
    }

    @Test
    fun `listing data decodes too, a field may stay Data, and a field the class needs but the type lacks throws`() {
        lay()
        val data = laid(outer)
        data.decode<Raw>().inner.decode<Inner>().hi mustBe 0xffffffffL
        assertThrows<SerializationException> { data.decode<Wrong>() }
    }

    @Test
    fun `a plain integer reads an enum by ordinal`() {
        builder.setBytes("0x401000", "02")
        val plain = laid(ByteDataType.dataType)
        plain.decode<Kind>() mustBe Kind.VIRTUAL
    }
}
