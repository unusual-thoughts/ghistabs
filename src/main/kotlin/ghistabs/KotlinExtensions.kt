package ghistabs

fun String.nullIfEmpty() = ifEmpty { null }
fun String.removePrefixOrNull(prefix: String): String? = when {
    startsWith(prefix) -> substring(prefix.length)
    else -> null
}

/** Consecutive runs sharing a [key] — `groupBy` would merge runs that aren't adjacent. */
fun <T, K> List<T>.chunkedBy(key: (T) -> K): List<List<T>> = fold(mutableListOf<MutableList<T>>()) { acc, item ->
    acc.lastOrNull()?.takeIf { key(it.first()) == key(item) }?.add(item) ?: acc.add(mutableListOf(item))
    acc
}
