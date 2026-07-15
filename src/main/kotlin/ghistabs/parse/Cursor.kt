package ghistabs.parse

import java.math.BigInteger

/**
 * A char cursor over a stabs descriptor string: peek/advance plus lexical token readers
 * (integers, range bounds, run-until-terminator). Carries no stabs grammar knowledge — the
 * grammar productions (and the C++-aware name readers) live in [Parser] as `Cursor` extensions.
 */
internal class Cursor(val src: String) {
    var pos: Int = 0
        private set

    val eof get() = pos >= src.length

    fun peek(): Char = if (eof) {
        throw StabsParseException(pos, src, "unexpected end of input")
    } else {
        src[pos]
    }

    fun peekOrNull(i: Int = 0): Char? = if (pos + i >= src.length) null else src[pos + i]

    fun peekFollows(prefix: String): Boolean = src.startsWith(prefix, pos)

    fun advance() = peek().apply { pos++ }

    /** Append the next [n] chars to the receiver builder. */
    fun StringBuilder.feed(n: Int = 1) = repeat(n) { append(advance()) }

    fun consume(c: Char) {
        if (eof || src[pos] != c) {
            throw StabsParseException(pos, src, "expected '$c' but got '${peekOrNull() ?: "<eof>"}'")
        }
        pos++
    }

    fun consumeIf(c: Char): Boolean {
        if (!eof && src[pos] == c) {
            pos++
            return true
        }
        return false
    }

    /** Read a (possibly negative) decimal integer terminated by a non-digit. */
    fun readInt(): Long {
        val start = pos
        if (!eof && (src[pos] == '-' || src[pos] == '+')) pos++
        val numStart = pos
        while (!eof && src[pos].isDigit()) pos++
        if (pos == numStart) throw StabsParseException(start, src, "expected integer")
        return src.substring(start, pos).toLong()
    }

    /**
     * Range bound: decimal or octal (leading `0` followed by another digit = octal).
     * Parsed via [BigInteger] then truncated to the low 64 bits, so `unsigned long long`'s
     * max (`01777777777777777777777` = -1L reinterpreted) and gcc 3.4.5's 128-bit `@s128`
     * bounds (`037777777777777777777777777777777`, 96+ bits) both fold to Long without
     * overflowing — the true width is carried by the size attribute, not the bound.
     */
    fun readRangeBound(): Long {
        val start = pos
        var sign = 1L
        if (!eof && (src[pos] == '-' || src[pos] == '+')) {
            if (src[pos] == '-') sign = -1L
            pos++
        }
        val numStart = pos
        while (!eof && src[pos].isDigit()) pos++
        if (pos == numStart) throw StabsParseException(start, src, "expected range bound")
        val raw = src.substring(numStart, pos)
        val radix = if (raw.length >= 2 && raw[0] == '0') 8 else 10
        // For the gcc unsigned-overflow form sign=+1 and 0xFFFF... reinterprets as -1L.
        return sign * BigInteger(raw, radix).toLong()
    }

    /** Read up to (but not including) any of the terminator chars. Consumed terminator is left in place. */
    fun readUntilAny(terminators: CharArray): String {
        val start = pos
        while (!eof && src[pos] !in terminators) pos++
        return src.substring(start, pos)
    }
}
