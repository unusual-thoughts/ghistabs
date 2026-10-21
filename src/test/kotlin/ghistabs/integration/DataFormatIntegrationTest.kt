package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Data
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.Deref
import ghistabs.Ptr
import ghistabs.SerialAddress
import ghistabs.SerialData
import ghistabs.SerialStructure
import ghistabs.decode
import ghistabs.get
import ghistabs.read
import ghistabs.readAs
import ghistabs.readAt
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
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
        val target: SerialAddress,
        val inner: Inner,
        val kind: Kind,
        val words: List<UShort>,
        val pairs: List<Inner>,
        val ptr: Ptr<Inner>,
        @Deref val pointed: Inner,
        @Deref val nothing: Inner?,
        val missing: Int? = null,
        val defaulted: String = "d",
    )

    @Serializable
    data class Raw(val inner: SerialData)

    @Serializable
    data class Wrong(val nope: Int)

    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    private val inner by lazy {
        SerialStructure<Inner>("Inner") {
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
        SerialStructure<Outer>("Outer") {
            add(IntegerDataType.dataType, "offset", null)
            add(PointerDataType(VoidDataType.dataType, 4), "target", null)
            add(TypedefDataType("Inner_t", inner), "inner", null)
            add(kind, "kind", null)
            add(ArrayDataType(UnsignedShortDataType.dataType, 3, 2), "words", null)
            add(ArrayDataType(inner, 2, inner.length), "pairs", null)
            listOf("ptr", "pointed", "nothing").forEach { add(PointerDataType(inner, 4), it, null) }
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
                "27 10 40 00 27 10 40 00 00 00 00 00",
            ).joinToString(" "),
        )
    }

    @Test
    fun `a structure reads into its class by field name, pointers followed, as does a SerialStructure's value`() {
        lay()
        val expected = Outer(
            offset = -4,
            target = builder.addr(0x402010),
            inner = Inner(-2, 0xffffffffL, isVirtual = true, access = 2),
            kind = Kind.PLAIN,
            words = listOf<UShort>(1u, 2u, 0xffffu),
            pairs = listOf(Inner(1, 2, isVirtual = false, access = 0), Inner(3, 4, isVirtual = true, access = 3)),
            ptr = Ptr(builder.addr(0x401027)) { null },
            pointed = Inner(3, 4, isVirtual = true, access = 3),
            nothing = null,
        )
        program.read<Outer>(builder.addr(0x401000), outer) mustBe expected
        program.readAs<Outer>(builder.addr(0x401000), outer)?.ptr?.deref() mustBe expected.pointed
        program.readAt(builder.addr(0x401000), outer)?.get("inner")?.value mustBe expected.inner
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

    @Serializable
    data class Probe(val ptr: Ptr<Inner>)

    @Test
    fun `a pointee that is unmapped, runs off its block or off the address space is null`() {
        builder.createMemory(".top", "0xffffff00", 0x100)
        val probe = SerialStructure<Probe>("Probe") { add(PointerDataType(inner, 4), "ptr", null) }
        listOf("00 00 50 00", "fc 10 40 00", "fc ff ff ff").forEach {
            builder.setBytes("0x401000", it)
            program.read<Probe>(builder.addr(0x401000), probe)?.ptr?.deref().mustBeNull(it)
        }
    }
}
