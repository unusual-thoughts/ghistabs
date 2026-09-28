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
 * the wp-unix corpus): each must read to zero types rather than throw, and never fall through to
 * the ELF `.symtab`.
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
     * reads, and harvests to nothing.
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

        val (_, harvester) = dummyHarvester()
        harvester.harvest(stabs.records).types.mustBeEmpty()

        val elf = blocks(".symtab", ".strtab", StabReader.INDEX, ".stab.indexstr")
        StabReader.candidate(elf = true, elf)?.records mustBe StabReader.INDEX
    }

    /** A binary with real stabs and an index too keeps reading the stabs. */
    @Test
    fun realStabsOutrankTheIndex() {
        val both = blocks(".stab", ".stabstr", StabReader.INDEX, ".stab.indexstr")
        StabReader.candidate(elf = true, both)?.records mustBe ".stab"
    }

    /**
     * `wpsputl_elf_sparc_sunsc42_indexonly`: a `.stab.index` whose `.stab.indexstr` is gone. Nothing
     * is read — in particular not the ELF `.symtab`, which is what the reader used to fall through to.
     */
    @Test
    fun indexWithoutStringsLocatesNothing() {
        val elf = blocks(".symtab", ".strtab", StabReader.INDEX)
        StabReader.candidate(elf = true, elf).mustBeNull()

        // The same symtab on a.out is the stab table, and still read.
        StabReader.candidate(elf = false, elf)?.layout mustBe Layout.SYMTAB
    }
}
