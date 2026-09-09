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

    /** Unconsumed tail after the last production returned. */
    val remaining get() = src.substring(pos)

    fun peek(i: Int = 0): Char? = src.getOrNull(pos + i)

    fun peekFollows(prefix: String): Boolean = src.startsWith(prefix, pos)

    fun nextNot(c: Char): Boolean = !eof && src[pos] != c

    fun advance() = if (eof) {
        throw StabsParseException(pos, src, "unexpected end of input")
    } else {
        src[pos++]
    }

    fun advanceOrNull() = peek()?.apply { pos++ }

    /** Append the next [n] chars to the receiver builder. */
    fun StringBuilder.feed(n: Int = 1) = repeat(n) { append(advance()) }

    fun consume(c: Char) {
        if (eof || src[pos] != c) {
            throw StabsParseException(pos, src, "expected '$c' but got '${peek() ?: "<eof>"}'")
        }
        pos++
    }

    fun consumeIf(prefix: String) = peekFollows(prefix).also { if (it) pos += prefix.length }

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
     * Range bound: decimal or octal (leading `0` followed by another digit = octal), exactly as
     * written. Not narrowed here — `unsigned long long`'s max (`01777777777777777777777`) is -1L in
     * 64 bits, indistinguishable from the literal `-1` an emitter writes when it declines to state
     * the bound. gcc 2.6.3 writes both in one CU: `unsigned int:t4=r1;0;-1;` is four bytes and
     * `long long unsigned int:t7=r1;0;01777…;` is eight. [TypeDecl.Range] narrows for the consumers
     * that want the wrap, and keeps these for the width.
     */
    fun readRangeBound(): BigInteger {
        val start = pos
        var sign = BigInteger.ONE
        if (!eof && (src[pos] == '-' || src[pos] == '+')) {
            if (src[pos] == '-') sign = sign.negate()
            pos++
        }
        val numStart = pos
        while (!eof && src[pos].isDigit()) pos++
        if (pos == numStart) throw StabsParseException(start, src, "expected range bound")
        val raw = src.substring(numStart, pos)
        val radix = if (raw.length >= 2 && raw[0] == '0') 8 else 10
        return sign * BigInteger(raw, radix)
    }

    /** Read up to (but not including) any of the terminator chars. Consumed terminator is left in place. */
    fun readUntilAny(terminators: CharArray): String {
        val start = pos
        while (!eof && src[pos] !in terminators) pos++
        return src.substring(start, pos)
    }
}

class StabsParseException(val pos: Int, val src: String, msg: String) :
    RuntimeException("at $pos in '$src': $msg") {
    /** Returns a one-line excerpt with a `^` caret at `pos`. */
    fun excerpt(): String {
        val start = (pos - 30).coerceAtLeast(0)
        val end = (pos + 30).coerceAtMost(src.length)
        val window = src.substring(start, end)
        val caret = " ".repeat(pos - start) + "^"
        return "$window\n$caret"
    }
}
