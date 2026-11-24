package ghicpp.stl

import ghidra.program.model.listing.Program
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The source languages a program's DWARF compile units declare (`DW_AT_language`), read off the first DIE
 * of each unit in `.debug_info`. A gcc 3 build linked on Debian etch carries DWARF only for glibc's start
 * files, C and assembler, which says nothing of the program's own classes.
 */
object DwarfLanguages {
    /** C++ in each standard's code, and Objective-C++. */
    private val CXX = setOf(0x04, 0x11, 0x19, 0x1a, 0x21)

    /**
     * Whether [program]'s DWARF describes C++, or might: a unit this reader cannot follow (a newer form,
     * compressed sections) counts as C++, as a program's own debug info is the safer guess.
     */
    fun describesCxx(program: Program): Boolean {
        val info = section(program, ".debug_info") ?: return program.memory.getBlock(".zdebug_info") != null
        val abbrev = section(program, ".debug_abbrev") ?: return true
        val order = if (program.language.isBigEndian) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val languages = of(info, abbrev, order) ?: return true
        return languages.any { it in CXX }
    }

    private fun section(program: Program, name: String): ByteArray? {
        val block = program.memory.getBlock(name)?.takeIf { it.isInitialized } ?: return null
        return ByteArray(block.size.toInt()).also { block.getBytes(block.start, it) }
    }

    /** Each unit's language, or null where a unit cannot be read; a unit that names none is left out. */
    fun of(info: ByteArray, abbrev: ByteArray, order: ByteOrder): List<Int>? = runCatching {
        val buf = ByteBuffer.wrap(info).order(order)
        val out = mutableListOf<Int>()
        while (buf.remaining() > 0) {
            val unit = Header.read(buf) ?: return null
            unit.language(buf, ByteBuffer.wrap(abbrev).order(order))?.let(out::add)
            buf.position(unit.end)
        }
        out
    }.getOrNull()

    private class Header(val end: Int, val version: Int, val offsetSize: Int, val addressSize: Int, val abbrev: Long) {
        /** The language its first DIE gives, [buf] at that DIE. */
        fun language(buf: ByteBuffer, abbrevs: ByteBuffer): Int? {
            val code = uleb(buf)
            abbrevs.position(abbrev.toInt())
            while (true) {
                val entry = uleb(abbrevs)
                check(entry != 0L) { "no abbreviation $code" }
                uleb(abbrevs)
                abbrevs.get()
                val attributes = generateSequence { (uleb(abbrevs) to uleb(abbrevs)).takeIf { it != 0L to 0L } }
                    .map { (attribute, form) ->
                        Triple(attribute, form, if (form == IMPLICIT.toLong()) sleb(abbrevs) else 0)
                    }
                    .toList()
                if (entry != code) continue
                for ((attribute, form, implicit) in attributes) {
                    val value = read(buf, form.toInt(), implicit)
                    if (attribute == LANGUAGE) return value?.toInt()
                }
                return null
            }
        }

        /** Reads one attribute of [form]: its value if it is a constant, else null. */
        private fun read(buf: ByteBuffer, form: Int, implicit: Long): Long? {
            FIXED[form]?.let { size ->
                val value = when (size) {
                    1 -> buf.get().toLong() and 0xff
                    2 -> buf.getShort().toLong() and 0xffff
                    4 -> buf.getInt().toLong() and 0xffffffffL
                    else -> null.also { buf.position(buf.position() + size) }
                }
                return value
            }
            when (form) {
                ADDR -> skip(buf, addressSize)
                REF_ADDR -> skip(buf, if (version == 2) addressSize else offsetSize)
                in OFFSETS -> skip(buf, offsetSize)
                UDATA -> return uleb(buf)
                SDATA -> return sleb(buf)
                in LEB -> uleb(buf)
                in BLOCKS -> skip(buf, uleb(buf).toInt())
                BLOCK1 -> skip(buf, buf.get().toInt() and 0xff)
                BLOCK2 -> skip(buf, buf.getShort().toInt() and 0xffff)
                BLOCK4 -> skip(buf, buf.getInt())
                STRING -> while (buf.get() != 0.toByte()) Unit
                INDIRECT -> return read(buf, uleb(buf).toInt(), implicit)
                IMPLICIT -> return implicit
                FLAG_PRESENT -> Unit
                else -> error("form $form")
            }
            return null
        }

        companion object {
            /** A unit header, [buf] left at its first DIE; null for one this reader does not know. */
            fun read(buf: ByteBuffer): Header? {
                var length = buf.getInt().toLong() and 0xffffffffL
                val offsetSize = if (length == 0xffffffffL) 8 else 4
                if (offsetSize == 8) length = buf.getLong()
                val end = buf.position() + length.toInt()
                val version = buf.getShort().toInt()
                return when (version) {
                    2, 3, 4 -> {
                        val abbrev = if (offsetSize == 8) buf.getLong() else buf.getInt().toLong()
                        Header(end, version, offsetSize, buf.get().toInt(), abbrev)
                    }

                    5 -> {
                        val type = buf.get().toInt()
                        val addressSize = buf.get().toInt()
                        val abbrev = if (offsetSize == 8) buf.getLong() else buf.getInt().toLong()
                        // A skeleton or split unit's id, or a type unit's signature and type offset.
                        when (type) {
                            DW_UT_COMPILE, DW_UT_PARTIAL -> Unit
                            DW_UT_SKELETON, DW_UT_SPLIT_COMPILE -> skip(buf, 8)
                            else -> skip(buf, 8 + offsetSize)
                        }
                        Header(end, version, offsetSize, addressSize, abbrev)
                    }

                    else -> null
                }
            }
        }
    }

    private const val LANGUAGE = 0x13L
    private const val ADDR = 0x01
    private const val BLOCK2 = 0x03
    private const val BLOCK4 = 0x04
    private const val BLOCK1 = 0x0a
    private const val STRING = 0x08
    private const val SDATA = 0x0d
    private const val UDATA = 0x0f
    private const val REF_ADDR = 0x10
    private const val INDIRECT = 0x16
    private const val FLAG_PRESENT = 0x19
    private const val IMPLICIT = 0x21
    private const val DW_UT_COMPILE = 1
    private const val DW_UT_PARTIAL = 3
    private const val DW_UT_SKELETON = 4
    private const val DW_UT_SPLIT_COMPILE = 5

    /** The forms of a fixed size, by form code. */
    private val FIXED = mapOf(
        0x05 to 2, 0x06 to 4, 0x07 to 8, 0x0b to 1, 0x0c to 1, 0x11 to 1, 0x12 to 2, 0x13 to 4, 0x14 to 8,
        0x1c to 4, 0x1e to 16, 0x20 to 8, 0x24 to 8, 0x25 to 1, 0x26 to 2, 0x27 to 3, 0x28 to 4, 0x29 to 1,
        0x2a to 2, 0x2b to 3, 0x2c to 4,
    )

    /** strp, sec_offset, strp_sup, line_strp, GNU_ref_alt, GNU_strp_alt: a section offset. */
    private val OFFSETS = setOf(0x0e, 0x17, 0x1d, 0x1f, 0x1f20, 0x1f21)

    /** ref_udata, strx, addrx, loclistx, rnglistx, GNU_addr_index, GNU_str_index. */
    private val LEB = setOf(0x15, 0x1a, 0x1b, 0x22, 0x23, 0x1f01, 0x1f02)

    /** block, exprloc: a ULEB128 length, then the bytes. */
    private val BLOCKS = setOf(0x09, 0x18)

    private fun skip(buf: ByteBuffer, n: Int) {
        buf.position(buf.position() + n)
    }

    private fun uleb(buf: ByteBuffer): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = buf.get().toInt()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
    }

    private fun sleb(buf: ByteBuffer): Long {
        var result = 0L
        var shift = 0
        var b: Int
        do {
            b = buf.get().toInt()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
        } while (b and 0x80 != 0)
        return if (shift < 64 && b and 0x40 != 0) result or (-1L shl shift) else result
    }
}
