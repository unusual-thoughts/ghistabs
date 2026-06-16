package ghistabs.parse

internal class Cursor(val src: String) {
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
     * Read a stabs range bound. GCC emits range bounds in either decimal
     * (`-2147483648`, `2147483647`) or octal (`0`, `0177777`,
     * `01777777777777777777777` for `unsigned long long`'s max). A leading
     * `0` followed by another digit indicates octal. Plain `0` is decimal zero.
     *
     * Octal `01777777777777777777777` (= 2^64-1 = -1L) overflows signed
     * decimal Long.toLong() but parses correctly via radix-8 with
     * `java.lang.Long.parseUnsignedLong`. We then re-interpret the unsigned
     * value as a signed `Long`.
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
        val isOctal = raw.length >= 2 && raw[0] == '0'
        val magnitude =
            if (isOctal) {
                java.lang.Long.parseUnsignedLong(raw, 8)
            } else {
                java.lang.Long.parseUnsignedLong(raw, 10)
            }
        // Reinterpret unsigned magnitude with sign applied. For the gcc
        // unsigned-overflow form (0..0xFFFFFFFFFFFFFFFF) sign is always +1
        // and the result equals -1L when magnitude == 0xFFFFFFFFFFFFFFFF.
        return sign * magnitude
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

    /**
     * Read the symbol name up to (but not including) the descriptor-separator `:`.
     * C++ names in template arguments may contain `::` scope operators; these are
     * included in the name. Only a single `:` (not followed by another `:`) terminates.
     */
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
     * Read an XRef tag name, which may contain `::` inside C++ template arguments.
     * Rules:
     *  - `::` INSIDE angle-bracket depth > 0 → include both colons in name
     *  - `::` at depth 0 OR single `:` at any depth → stop (terminator is the first `:`)
     */
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

                ':' -> break

                // single ':' or '::' at depth 0 — stop before it
                else -> {
                    sb.append(ch)
                    pos++
                }
            }
        }
        return sb.toString()
    }

    fun restore(saved: Int) {
        pos = saved
    }
}
