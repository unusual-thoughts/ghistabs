package ghistabs

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
