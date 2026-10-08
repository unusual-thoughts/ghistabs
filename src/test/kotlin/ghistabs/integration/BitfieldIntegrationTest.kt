package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.BitFieldDataType
import ghidra.program.model.data.Structure
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.StabsImporter
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.test.defaultContext
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** A stab field whose `bitsize` is narrower than its type, or whose `bitpos` is not byte-aligned, is a bitfield. */
@Tag("integration")
class BitfieldIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private var builder: ProgramBuilder? = null

    @AfterEach
    fun tearDown() = builder?.dispose() ?: Unit

    private fun struct(name: String, vararg stabs: String, language: String = ProgramBuilder._X86): Structure {
        val program = ProgramBuilder("test", language).also { builder = it }
            .apply { createMemory(".text", "0x400000", 1024) }.program
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "hello.cc")) +
            stabs.mapIndexed { i, s -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, s) }
        StabsImporter(program.defaultContext()).runOnRecords(StabReader.Result(records))
        return program.dataTypeManager.allStructures.asSequence().single { it.name == name }
    }

    /** (name, bit from the struct's start in memory order, width) for each component: from the first byte's
     *  least significant bit on little-endian, its most significant on big-endian, as the stab counts. */
    private fun Structure.bits() = definedComponents.map { c ->
        when (val dt = c.dataType) {
            is BitFieldDataType if dataOrganization.isBigEndian ->
                Triple(c.fieldName, c.offset * 8 + c.length * 8 - dt.bitOffset - dt.bitSize, dt.bitSize)

            is BitFieldDataType -> Triple(c.fieldName, c.offset * 8 + dt.bitOffset, dt.bitSize)

            else -> Triple(c.fieldName, c.offset * 8, c.length * 8)
        }
    }

    /** `features/hello.cc`: `struct Flags { unsigned ro : 1, hidden : 1, mode : 3; signed prio : 4; };`, gcc 12. */
    @Test
    fun `hello's Flags keeps all four bitfields in four bytes`() {
        val flags = struct(
            "Flags",
            "int:t(0,1)=r(0,1);-2147483648;2147483647;",
            "Flags:Tt(0,11)=s4ro:(0,37)=r(0,37);0;037777777777;,0,1;hidden:(0,37),1,1;mode:(0,37),2,3;" +
                "prio:(0,1),5,4;;",
        )
        flags.length mustBe 4
        flags.bits() mustBe listOf(
            Triple("ro", 0, 1),
            Triple("hidden", 1, 1),
            Triple("mode", 2, 3),
            Triple("prio", 5, 4),
        )
    }

    /** winnt.h `_LDT_ENTRY.HighWord.Bits` on crypto_mi_test_gcc421_fullstabs: byte-aligned fields narrower than
     *  their `DWORD` are bitfields too, and lay end to end within the stab's four bytes. */
    @Test
    fun `byte-aligned fields narrower than their type stay within the struct`() {
        val bits = struct(
            "Bits",
            "long unsigned int:t(0,5)=r(0,5);0;4294967295;",
            "DWORD:t(0,627)=(0,5)",
            "Bits:T(0,1816)=s4BaseMid:(0,627),0,8;Type:(0,627),8,5;Dpl:(0,627),13,2;Pres:(0,627),15,1;" +
                "LimitHi:(0,627),16,4;Sys:(0,627),20,1;Reserved_0:(0,627),21,1;Default_Big:(0,627),22,1;" +
                "Granularity:(0,627),23,1;BaseHi:(0,627),24,8;;",
        )
        bits.length mustBe 4
        bits.bits() mustBe listOf(
            Triple("BaseMid", 0, 8),
            Triple("Type", 8, 5),
            Triple("Dpl", 13, 2),
            Triple("Pres", 15, 1),
            Triple("LimitHi", 16, 4),
            Triple("Sys", 20, 1),
            Triple("Reserved_0", 21, 1),
            Triple("Default_Big", 22, 1),
            Triple("Granularity", 23, 1),
            Triple("BaseHi", 24, 8),
        )
    }

    /**
     * gcc 2.8.1's `__class_type_info::base_info` on SPARC (`wp-unix/cv_mscom_elf_sparc_gcc281`), whose
     * `dcast` reads `offset` as `word >> 3`, `is_virtual` as `word & 4` and `access` as `word & 3`: a
     * big-endian bitpos counts from the most significant bit. The i386 twin emits the same stab and reads
     * `word & 0x1fffffff`.
     */
    @Test
    fun `a big-endian bitpos counts from the most significant bit`() {
        val info = struct(
            "base_info",
            "unsigned int:t(0,4)=r(0,4);0;-1;",
            "bool:t(0,19)=@s32;-16;",
            "access:t(0,18)=ePUBLIC:1,PROTECTED:2,PRIVATE:3,;",
            "base_info:Tt(0,20)=s8base:(0,21)=*(0,4),0,32;offset:(0,4),32,29;is_virtual:(0,19),61,1;" +
                "access:(0,18),62,2;;",
            language = "sparc:BE:32:default",
        )
        info.length mustBe 8
        info.bits() mustBe listOf(
            Triple("base", 0, 32),
            Triple("offset", 32, 29),
            Triple("is_virtual", 61, 1),
            Triple("access", 62, 2),
        )
        val offset = info.definedComponents[1]
        (offset.offset to (offset.dataType as BitFieldDataType).bitOffset) mustBe (4 to 3)
    }
}
