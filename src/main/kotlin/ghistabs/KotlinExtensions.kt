package ghistabs

import kotlin.math.abs

fun String.nullIfEmpty() = ifEmpty { null }
fun String.removePrefixOrNull(prefix: String): String? = when {
    startsWith(prefix) -> substring(prefix.length)
    else -> null
}

inline fun <T> List<T>.chunkNotNull(f: (List<T>?, T) -> Boolean?) = fold(mutableListOf<MutableList<T>>()) { acc, item ->
    acc.apply {
        val prev = lastOrNull()
        when (f(prev, item)) {
            null -> {}
            true -> prev?.add(item)
            false -> acc.add(mutableListOf(item))
        }
    }
} as List<List<T>>

inline fun <T> List<T>.chunkOf(f: (List<T>, T) -> Boolean) = chunkNotNull { prev, item ->
    prev != null && f(prev, item)
}

inline fun <T> List<T>.chunkWith(eq: (T, T) -> Boolean) = chunkOf { acc, item -> eq(acc.last(), item) }

/** Consecutive runs sharing a [key] — `groupBy` would merge runs that aren't adjacent. */
inline fun <T, K> List<T>.chunkedBy(key: (T) -> K) = chunkWith { a, b -> key(a) == key(b) }

/**
 * Runs past `E` for [Double]'s sake: a `Long` tops out at 9.22E
 * but zetta and yotta are ordinary magnitudes for a double
 */
private const val SI_PREFIXES = "KMGTPEZY"

/**
 * [this] in at most [maxWidth] columns, spending whatever they allow on decimals and taking an SI
 * prefix once the integer part alone won't fit: `12.50`, `148K`, `1.23M`, `-9.2E`. Null [maxWidth]
 * gives the plain [toString].
 *
 * Truncates rather than rounds — rounding `999.95K` up would carry into `1000.0K` and spend a column
 * the caller said it didn't have.
 */
fun Double.formatSi(maxWidth: Int? = null): String {
    if (maxWidth == null) return toString()

    val sign = if (this < 0) "-" else ""
    var value = abs(this)
    var prefix = ""
    for (p in SI_PREFIXES) {
        if (value < 1000) break
        value /= 1000
        prefix = p.toString()
    }

    val whole = value.toLong()
    // Whatever [maxWidth] has left once the sign, the prefix, the integer part and the `.` are spent.
    val decimals = (maxWidth - sign.length - prefix.length - whole.toString().length - 1).coerceAtLeast(0)
    val fraction = when (decimals) {
        0 -> ""
        else -> {
            val scale = generateSequence(1L) { it * 10 }.elementAt(decimals)
            ".${((value - whole) * scale).toLong().toString().padStart(decimals, '0')}"
        }
    }
    return "$sign$whole$fraction$prefix"
}

/**
 * The exact digits while they fit in [maxWidth], and [Double.formatSi]'s approximation once they
 * don't. Handing the whole job to [Double] would print `12345` as `12345.0`, and past 2^53 print
 * digits the value doesn't have — below that threshold nothing survives the abbreviation anyway.
 *
 * Scaling in [Double] is also what makes `Long.MIN_VALUE` work at all: its `absoluteValue` is still
 * negative, so every magnitude comparison on it inverts.
 */
fun Long.formatSi(maxWidth: Int? = null): String =
    toString().takeIf { maxWidth == null || it.length <= maxWidth } ?: toDouble().formatSi(maxWidth)

private val kebabRegex = "-[a-zA-Z]".toRegex()
fun String.kebabToCamelCase(): String = kebabRegex.replace(this) {
    it.value.replace("-", "").uppercase()
}
