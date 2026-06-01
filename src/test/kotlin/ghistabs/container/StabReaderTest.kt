package ghistabs.container

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class StabReaderTest {
    private object Fixture {
        /**
         * Build a single stab record's 12 bytes.
         */
        fun stabRecord(strx: Int, type: Int, other: Int, desc: Int, value: Int): ByteArray {
            val buf = ByteBuffer.allocate(STAB_RECORD_SIZE).apply {
                order(ByteOrder.LITTLE_ENDIAN)
            }
            buf.putInt(strx)
            buf.put(type.toByte())
            buf.put(other.toByte())
            buf.putShort(desc.toShort())
            buf.putInt(value)
            return buf.array()
        }

        /**
         * Concatenate multiple stab records.
         */
        fun stabSection(records: List<ByteArray>): ByteArray = records.fold(ByteArray(0)) { acc, r -> acc + r }

        /**
         * Build a stabstr with NUL-terminated strings.
         * Strings are concatenated with implicit NUL terminators.
         */
        fun stabstrSection(strings: List<String>): ByteArray {
            val buf = mutableListOf<Byte>()
            for (str in strings) {
                buf.addAll(str.toByteArray(Charsets.UTF_8).toList())
                buf.add(0.toByte()) // NUL terminator
            }
            return buf.toByteArray()
        }
    }

    /**
     * AC1.1: Single-CU fixture with multiple records is fully read.
     * Record count matches; names are non-empty.
     */
    @Test
    fun testAC1_1_single_cu_full_read() {
        // Build: N_UNDF header + 4 N_LSYM records
        // stabstr will be: "var1\0var2\0var3\0var4\0"
        // Offsets:         0    5    10   15   20
        val undfRec = Fixture.stabRecord(strx = 0, type = 0x00, other = 0, desc = 0, value = 20)
        val lsym1 = Fixture.stabRecord(strx = 0, type = 0x80, other = 1, desc = 100, value = 1000)
        val lsym2 = Fixture.stabRecord(strx = 5, type = 0x80, other = 2, desc = 101, value = 1001)
        val lsym3 = Fixture.stabRecord(strx = 10, type = 0x80, other = 3, desc = 102, value = 1002)
        val lsym4 = Fixture.stabRecord(strx = 15, type = 0x80, other = 4, desc = 103, value = 1003)

        val stab = Fixture.stabSection(listOf(undfRec, lsym1, lsym2, lsym3, lsym4))

        // stabstr: "var1\0var2\0var3\0var4\0" (lengths: 5, 5, 5, 5)
        val stabstr = Fixture.stabstrSection(listOf("var1", "var2", "var3", "var4"))

        val reader = StabReader(stab, stabstr)
        val result = reader.readAll()

        // Expect 5 records (1 N_UNDF + 4 N_LSYM, no continuation merging)
        assertEquals(5, result.records.size, "records size")
        assertEquals(5, result.recordCount, "physical record count")
        assertEquals(0, result.truncatedTail, "no truncated tail")

        // Check N_UNDF
        assertEquals(StabType.N_UNDF, result.records[0].type)
        assertEquals("", result.records[0].name)

        // Check N_LSYM records
        assertEquals("var1", result.records[1].name)
        assertEquals("var2", result.records[2].name)
        assertEquals("var3", result.records[3].name)
        assertEquals("var4", result.records[4].name)
    }

    /**
     * AC1.1 (continuation case): Chain of 3 N_FUN records where first two end in `\`.
     * After reassembly, expect ONE record with concatenated name.
     */
    @Test
    fun testAC1_1_continuation_merging() {
        // Build: N_UNDF header + 3 N_FUN records (2 with continuation, 1 final)
        // stabstr will be: "foo\\\0middle\\\0tail\0"
        // "foo\\" = 4 bytes + NUL = 5 bytes (offset 0)
        // "middle\\" = 7 bytes + NUL = 8 bytes (offset 5)
        // "tail" = 4 bytes + NUL = 5 bytes (offset 13)
        // Total = 18 bytes
        val undfRec = Fixture.stabRecord(strx = 0, type = 0x00, other = 0, desc = 0, value = 18)
        val fun1 = Fixture.stabRecord(strx = 0, type = 0x24, other = 1, desc = 100, value = 1000)
        val fun2 = Fixture.stabRecord(strx = 5, type = 0x24, other = 0, desc = 0, value = 0)
        val fun3 = Fixture.stabRecord(strx = 13, type = 0x24, other = 0, desc = 0, value = 0)

        val stab = Fixture.stabSection(listOf(undfRec, fun1, fun2, fun3))

        // stabstr: "foo\\\0middle\\\0tail\0"
        val stabstr = Fixture.stabstrSection(listOf("foo\\", "middle\\", "tail"))

        val reader = StabReader(stab, stabstr)
        val result = reader.readAll()

        // Expect 2 records (1 N_UNDF + 1 merged N_FUN)
        assertEquals(2, result.records.size, "records size")
        assertEquals(4, result.recordCount, "physical record count (1 UNDF + 3 FUN)")
        assertEquals(0, result.truncatedTail)

        // Check merged N_FUN: "foo\\" -> "foo" + "middle\\" -> "middle" + "tail" -> "tail"
        val merged = result.records[1]
        assertEquals(StabType.N_FUN, merged.type)
        assertEquals("foomiddletail", merged.name)
        assertEquals(1, merged.recordIndex, "first physical record index after UNDF")
    }

    /**
     * AC1.2: Two-CU fixture with per-CU stabstr offset trick.
     * CU1: N_UNDF.value=10, then stab with n_strx=6 resolves to stabstr[0+6=6..].
     * CU2: N_UNDF.value=8, then stab with n_strx=0 resolves to stabstr[10+0=10..].
     */
    @Test
    fun testAC1_2_two_cu_per_cu_offset() {
        // CU1: stabstr[0..10) = "apple\0xyz\0" (apple=6 bytes with NUL, xyz=4 bytes with NUL = 10 total)
        // CU2: stabstr[10..18) = "banana\0x\0" (banana=7 bytes with NUL, x=2 bytes = 9 total, pad to 8)
        val cu1Undf = Fixture.stabRecord(strx = 0, type = 0x00, other = 0, desc = 0, value = 10)
        val cu1Lsym = Fixture.stabRecord(strx = 6, type = 0x80, other = 1, desc = 100, value = 1000)

        val cu2Undf = Fixture.stabRecord(strx = 0, type = 0x00, other = 0, desc = 0, value = 8)
        val cu2Lsym = Fixture.stabRecord(strx = 0, type = 0x80, other = 2, desc = 101, value = 1001)

        val stab = Fixture.stabSection(listOf(cu1Undf, cu1Lsym, cu2Undf, cu2Lsym))

        // Build stabstr: CU1 gets 10 bytes, CU2 gets 8 bytes
        // CU1: "apple\0xyz\0" (6 + 4 = 10 bytes)
        // CU2: "banana\0x\0" (7 + 2 = 9 bytes, but CU2 size is 8, so we'll use only first 8)
        val stabstr = ByteArray(18)
        val cu1Str =
            "apple".toByteArray(Charsets.UTF_8) + byteArrayOf(0) + "xyz".toByteArray(Charsets.UTF_8) + byteArrayOf(0)
        val cu2Str = "banana".toByteArray(Charsets.UTF_8) + byteArrayOf(0, 0)
        cu1Str.copyInto(stabstr, 0)
        cu2Str.copyInto(stabstr, 10)

        val reader = StabReader(stab, stabstr)
        val result = reader.readAll()

        // Expect 4 records: 2 N_UNDF headers + 2 N_LSYM
        assertEquals(4, result.records.size)
        assertEquals(4, result.recordCount)

        // Check CU1 LSYM: stabstr[0+6=6..] = "xyz"
        val cu1Record = result.records[1]
        assertEquals("xyz", cu1Record.name, "CU1 LSYM should read from CU1's stabstr")

        // Check CU2 LSYM: stabstr[10+0=10..] = "banana"
        val cu2Record = result.records[3]
        assertEquals("banana", cu2Record.name, "CU2 LSYM should read from CU2's stabstr")
    }

    /**
     * Unknown n_type byte is treated as StabType.UNKNOWN with rawType carrying the byte.
     */
    @Test
    fun testUnknownType() {
        val undfRec = Fixture.stabRecord(strx = 0, type = 0x00, other = 0, desc = 0, value = 10)
        val unknownRec = Fixture.stabRecord(strx = 0, type = 0xAB, other = 1, desc = 100, value = 1000)

        val stab = Fixture.stabSection(listOf(undfRec, unknownRec))
        val stabstr = Fixture.stabstrSection(listOf("test"))

        val reader = StabReader(stab, stabstr)
        val result = reader.readAll()

        assertEquals(2, result.records.size)
        val unknownRecord = result.records[1]
        assertEquals(StabType.UNKNOWN, unknownRecord.type)
        assertEquals(0xAB, unknownRecord.rawType)
        assertEquals("test", unknownRecord.name)
    }

    /**
     * Truncated tail (stab size not multiple of 12) is skipped.
     */
    @Test
    fun testTruncatedTail() {
        val undfRec = Fixture.stabRecord(strx = 0, type = 0x00, other = 0, desc = 0, value = 5)
        val lsymRec = Fixture.stabRecord(strx = 0, type = 0x80, other = 1, desc = 100, value = 1000)

        var stab = Fixture.stabSection(listOf(undfRec, lsymRec))
        // Append 5 bogus bytes
        stab += byteArrayOf(0, 1, 2, 3, 4)

        val stabstr = Fixture.stabstrSection(listOf("var"))

        val reader = StabReader(stab, stabstr)
        val result = reader.readAll()

        // Should have read the 2 complete records, ignore the 5-byte tail
        assertEquals(2, result.records.size)
        assertEquals(2, result.recordCount)
        assertEquals(5, result.truncatedTail)
    }

    /**
     * Empty .stab (zero-length input).
     */
    @Test
    fun testEmptyStab() {
        val stab = byteArrayOf()
        val stabstr = byteArrayOf()

        val reader = StabReader(stab, stabstr)
        val result = reader.readAll()

        assertEquals(0, result.records.size)
        assertEquals(0, result.recordCount)
        assertEquals(0, result.truncatedTail)
    }
}
