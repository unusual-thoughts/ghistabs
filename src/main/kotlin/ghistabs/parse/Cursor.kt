package ghistabs.parse

import java.math.BigInteger

internal class Cursor(val src: String) {
    companion object {
        // Symbol chars that may follow `operator` in a method name (arithmetic, logical,
        // comparison, shift). Brackets/parens/comma are excluded — they carry no `<>` and
        // need no protection from template-depth tracking.
        private const val OPERATOR_SYMBOLS = "+-*/%^&|~!=<>"
    }

    var pos: Int = 0
        private set

    val eof get() = pos >= src.length

    fun peek(): Char = if (eof) {
        throw StabsParseException(pos, src, "unexpected end of input")
    } else {
        src[pos]
    }

    fun peekOrNull(): Char? = if (eof) null else src[pos]

    fun advance(): Char {
        val c = peek()
        pos++
        return c
    }

    fun startsWith(prefix: String): Boolean = src.startsWith(prefix, pos)

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

    fun expect(s: String) {
        if (!startsWith(s)) throw StabsParseException(pos, src, "expected '$s'")
        pos += s.length
    }

    /** Read a (possibly negative) decimal integer terminated by a non-digit. */
    fun parseInt(): Long {
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
    fun parseRangeBound(): Long {
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

    /** Read `(cu,n)` or bare `n`. */
    fun parseTypeId(): LocalTypeId {
        if (consumeIf('(')) {
            val cu = parseInt().toInt()
            consume(',')
            val n = parseInt().toInt()
            consume(')')
            return LocalTypeId(cu, n)
        }
        val n = parseInt().toInt()
        return LocalTypeId(0, n)
    }

    /** Read up to (but not including) any of the terminator chars. Consumed terminator is left in place. */
    fun readUntilAny(terminators: CharArray): String {
        val start = pos
        while (!eof && src[pos] !in terminators) pos++
        return src.substring(start, pos)
    }

    /** Read up to the descriptor `:`. `::` (C++ scope) is preserved; only a single `:` terminates. */
    fun readSymbolName(): String {
        val sb = StringBuilder()
        while (!eof) {
            if (src[pos] == ':') {
                if (pos + 1 < src.length && src[pos + 1] == ':') {
                    sb.append(':')
                    pos++
                    sb.append(':')
                    pos++
                } else {
                    break
                }
            } else {
                sb.append(src[pos])
                pos++
            }
        }
        return sb.toString()
    }

    /**
     * Read a struct member / base-class name up to the terminating `:` or `/` at template
     * depth 0. Two wrinkles gcc emits inside such names:
     *  - a base class spelled out as a pseudo-field carries qualified template args, e.g.
     *    `AllocatorBase<CryptoPP::word16>` — the `::` there is part of the name, not a
     *    method marker, so `::` inside `<...>` is consumed;
     *  - `operator<`, `operator<<`, `operator>=`, … keep their angle brackets as operator
     *    tokens rather than opening template depth (they are unbalanced otherwise).
     */
    fun readMemberName(): String {
        val sb = StringBuilder()
        var depth = 0
        while (!eof) {
            val ch = src[pos]
            when {
                depth == 0 && startsWith("operator") && (pos + 8) < src.length && src[pos + 8] in OPERATOR_SYMBOLS -> {
                    repeat(8) {
                        sb.append(src[pos])
                        pos++
                    }
                    while (!eof && src[pos] in OPERATOR_SYMBOLS) sb.append(advance())
                }

                ch == '<' -> {
                    sb.append(advance())
                    depth++
                }
                ch == '>' -> {
                    sb.append(advance())
                    if (depth > 0) depth--
                }
                ch == ':' && depth > 0 && pos + 1 < src.length && src[pos + 1] == ':' -> {
                    sb.append(advance())
                    sb.append(advance())
                }

                ch == ':' -> break
                ch == '/' && depth == 0 -> break
                else -> sb.append(advance())
            }
        }
        return sb.toString()
    }

    /** Read an XRef tag name. `::` is preserved only inside `<>` template-arg depth > 0. */
    fun readXRefTagName(): String {
        val sb = StringBuilder()
        var depth = 0
        while (!eof) {
            when (val ch = src[pos]) {
                '<' -> {
                    sb.append(ch)
                    pos++
                    depth++
                }

                '>' -> {
                    sb.append(ch)
                    pos++
                    if (depth > 0) depth--
                }

                ':' if pos + 1 < src.length && src[pos + 1] == ':' && depth > 0 -> {
                    sb.append(':')
                    pos++
                    sb.append(':')
                    pos++
                }

                ':' -> break // single `:` or `::` at depth 0

                else -> {
                    sb.append(ch)
                    pos++
                }
            }
        }
        return sb.toString()
    }
}
