package ghistabs.harvest

import ghistabs.parse.STAB_RECORD_SIZE
import ghistabs.parse.StabReader
import ghistabs.parse.StabReader.Layout
import ghistabs.parse.StabType
import ghistabs.test.dummyHarvester
import ghistabs.test.mustBe
import ghistabs.test.mustBeEmpty
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The SunPro binaries whose linker kept only a per-CU `.stab.index` (the `_indexonly` samples in
 * the wp-unix corpus): each must read to zero types rather than throw, with a verdict saying why,
 * and never fall through to the ELF `.symtab`. Plus the two ways a wrong source used to crash:
 * records outside any `N_SO`, and `n_strx` past the table.
 */
class IndexOnlyStabsTest {
    private fun record(strx: Int, type: StabType, desc: Int = 0, value: Int = 0): ByteArray =
        ByteBuffer.allocate(STAB_RECORD_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(strx).put(type.code.toByte()).put(0.toByte()).putShort(desc.toShort()).putInt(value).array()

    private fun strings(vararg s: String) = s.fold(byteArrayOf(0)) { acc, str -> acc + str.toByteArray() + 0.toByte() }

    private fun blocks(vararg names: String): (String) -> Boolean = names.toSet()::contains

    /**
     * `inww8_elf_{sparc,i386}_*_indexonly`: an `N_UNDF` header naming each CU, then its `N_OPT`, the
     * compile command line (0x34) and an `N_MAIN`. No `N_SO` anywhere, and nothing to type — so it
     * reads, harvests to nothing, and the verdict says the stabs stayed in the objects.
     */
    @Test
    fun indexReadsToZeroTypes() {
        // "\0tmmain.c\0Xa ; V=3.1\0/src; cc -c tmmain.c\0main\0" — offsets 0, 1, 10, 21, 42.
        val str = strings("tmmain.c", "Xa ; V=3.1", "/src; cc -c tmmain.c", "main")
        val index = listOf(
            record(1, StabType.N_UNDF, desc = 3, value = str.size),
            record(10, StabType.N_OPT),
            record(21, StabType.N_NOMAP),
            record(42, StabType.N_MAIN),
        ).reduce(ByteArray::plus)

        val stabs = StabReader(index, str).readAll()
        stabs.records.map { it.name } mustBe listOf("tmmain.c", "Xa ; V=3.1", "/src; cc -c tmmain.c", "main")
        stabs.unresolvedNames mustBe 0

        val (sink, harvester) = dummyHarvester()
        harvester.harvest(stabs.records).types.mustBeEmpty()
        sink.counts["record-outside-cu"].mustBeNull()

        val elf = blocks(".symtab", ".strtab", ".stab.index", ".stab.indexstr")
        StabReader.candidate(elf = true, elf)?.records mustBe ".stab.index"
        StabReader.verdict(elf = true, elf)?.category mustBe "stab-index-only"
    }

    /** A binary with real stabs and an index too keeps reading the stabs, and needs no verdict. */
    @Test
    fun realStabsOutrankTheIndex() {
        val both = blocks(".stab", ".stabstr", ".stab.index", ".stab.indexstr")
        StabReader.candidate(elf = true, both)?.records mustBe ".stab"
        StabReader.verdict(elf = true, both).mustBeNull()
    }

    /**
     * `wpsputl_elf_sparc_sunsc42_indexonly`: a `.stab.index` whose `.stab.indexstr` is gone. Nothing
     * is read — in particular not the ELF `.symtab`, which is what the reader used to fall through to.
     */
    @Test
    fun indexWithoutStringsLocatesNothing() {
        val elf = blocks(".symtab", ".strtab", ".stab.index")
        StabReader.candidate(elf = true, elf).mustBeNull()
        StabReader.verdict(elf = true, elf)?.category mustBe "stab-strings-missing"

        // The same symtab on a.out is the stab table, and still read.
        StabReader.candidate(elf = false, elf)?.layout mustBe Layout.SYMTAB
    }

    /**
     * What reading the ELF `.symtab` as `nlist` handed the harvester on SPARC: symbols and lines with
     * no `N_SO` before them. Each is skipped with a diagnostic, instead of `cu` throwing.
     */
    @Test
    fun recordsOutsideAnyCuAreSkipped() {
        val str = strings("x:G(0,1)", "int:t(0,1)=r(0,1);-2147483648;2147483647;")
        val stab = listOf(
            record(0, StabType.N_UNDF, value = str.size),
            record(1, StabType.N_GSYM),
            record(10, StabType.N_LSYM),
            record(0, StabType.N_SLINE, desc = 7, value = 0x1000),
        ).reduce(ByteArray::plus)

        val (sink, harvester) = dummyHarvester()
        val harvest = harvester.harvest(StabReader(stab, str).readAll().records)

        harvest.types.mustBeEmpty()
        sink.counts["record-outside-cu"] mustBe 3L
    }

    /**
     * What it handed the reader on i386: an `n_strx` past the end of the string table, which threw
     * `EOFException` mid-read. The record keeps its place, nameless, and is counted.
     */
    @Test
    fun stringOffsetPastTableReadsNameless() {
        val str = strings("ok")
        val stab = listOf(
            record(0, StabType.N_UNDF, value = str.size),
            record(1, StabType.N_OPT),
            record(0x110000, StabType.N_OPT),
        ).reduce(ByteArray::plus)

        val stabs = StabReader(stab, str).readAll()

        stabs.records.map { it.name } mustBe listOf("", "ok", "")
        stabs.unresolvedNames mustBe 1
    }
}
