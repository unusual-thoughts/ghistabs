package ghistabs.cpp.eh

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.cpp.eh.SjljLsda.Kind
import ghistabs.minus
import ghistabs.plus
import ghistabs.test.mustBe
import ghistabs.test.mustBeEmpty
import ghistabs.test.mustBeNull
import ghistabs.test.mustBeTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** Reads through the program's memory, as the analyzer does, so it needs a program to read from. */
@Tag("integration")
class SjljLsdaTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("lsda", ProgramBuilder._X86, "gcc", this)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun code(vararg b: Int) = b.map { it.toByte() }.toByteArray()

    private var blocks = 0

    /** [b] alone in a block of its own, so a read past its end fails as it would off a section. */
    private fun parse(b: ByteArray): SjljLsda? {
        val start = "0x${(0x1000 * ++blocks).toString(16)}"
        val block = builder.createMemory("lsda$blocks", start, b.size)
        builder.setBytes(start, b)
        return SjljLsda.parse(builder.program, block.start)
    }

    /**
     * `xmltest_gcc345.exe`'s LSDA at 0x447408: six call sites, a cleanup-only one among them; a
     * `throw()` spec reached alone and as the tail of a `catch (...)` chain; one type, null; one byte
     * of padding before it.
     */
    private val xmltest = code(
        0xff, 0x00, 0x19, 0x01, 0x0c,
        0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x03, 0x03, 0x01, 0x04, 0x05,
        0x7f, 0x00, 0x7f, 0x7d, 0x01, 0x00,
        0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
    )

    @Test
    fun readsTheCallSitesActionsAndTypes() {
        val lsda = parse(xmltest)!!
        lsda.callSites.map { it.landingPad to it.action }
            .mustBe(listOf(0L to 0L, 1L to 1L, 1L to 0L, 2L to 3L, 3L to 1L, 4L to 5L))
        lsda.actions.map { Triple(it.at - lsda.start, it.filter, it.next) }.mustBe(
            listOf(Triple(17L, -1L, 0L), Triple(19L, -1L, -3L), Triple(21L, 1L, 0L)),
        )
        lsda.typeCount.mustBe(1)
        lsda.size.mustBe(29L)
    }

    /** Each call site's chain followed through its next-action references, and the spec's type list. */
    @Test
    fun followsEachCallSitesActionChain() {
        val lsda = parse(xmltest)!!
        lsda.callSites.map { lsda.filters(it) }
            .mustBe(listOf(emptyList(), listOf(-1L), emptyList(), listOf(-1L, -1L), listOf(-1L), listOf(1L)))
        lsda.specs.mustBe(mapOf(-1L to emptyList()))
        (lsda.typeAt(1, 4)!! - lsda.start).mustBe(24L)
    }

    @Test
    fun laysEveryByteOnce() {
        val lsda = parse(xmltest)!!
        val items = lsda.items
        items.map { it.at - lsda.start to it.kind }.mustBe(
            listOf(0L to Kind.ENCODING, 1L to Kind.ENCODING, 2L to Kind.ULEB128) +
                listOf(3L to Kind.ENCODING, 4L to Kind.ULEB128) +
                (5L..16L).map { it to Kind.ULEB128 } +
                (17L..22L).map { it to Kind.SLEB128 } +
                listOf(23L to Kind.ALIGNMENT, 24L to Kind.POINTER, 28L to Kind.ULEB128),
        )
        items.zipWithNext().all { (a, b) -> a.at + a.length == b.at }.mustBeTrue("gap or overlap in $items")
        items.single { it.kind == Kind.POINTER }.comment.mustBe("(LSDA Type 1) catch (...)")
        items.last().comment.mustBe("(LSDA Exception Spec) Type Index")
    }

    /** No type table: `ttype` omitted, and only cleanups, which need none. */
    @Test
    fun readsACleanupOnlyTable() {
        val lsda = parse(code(0xff, 0xff, 0x01, 0x04, 0x00, 0x00, 0x01, 0x00))!!
        lsda.callSites.size.mustBe(2)
        lsda.actions.mustBeEmpty()
        lsda.typeCount.mustBe(0)
        lsda.size.mustBe(8L)
    }

    /** A landing pad index past 127 takes a two-byte LEB128. */
    @Test
    fun readsAMultiByteIndex() {
        val lsda = parse(code(0xff, 0xff, 0x01, 0x03, 0xac, 0x02, 0x00))!!
        lsda.callSites.single().landingPad.mustBe(300L)
        lsda.size.mustBe(7L)
    }

    @Test
    fun rejectsWhatIsNotAnSjljLsda() {
        // An lpstart: SJLJ landing pads are indices, gcc never gives one.
        parse(code(0x00, 0xff, 0x01, 0x02, 0x00, 0x00)).mustBeNull()
        // DWARF call sites (udata4), as a `.eh_frame` LSDA has.
        parse(code(0xff, 0xff, 0x03, 0x02, 0x00, 0x00)).mustBeNull()
        // A record running past the call-site table's length.
        parse(code(0xff, 0xff, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00)).mustBeNull()
        // Truncated mid-table.
        parse(code(0xff, 0xff, 0x01, 0x04, 0x00, 0x00)).mustBeNull()
        // A catch with no type table to catch from.
        parse(code(0xff, 0xff, 0x01, 0x02, 0x00, 0x01, 0x01, 0x00)).mustBeNull()
    }
}
