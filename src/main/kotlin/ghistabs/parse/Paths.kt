package ghistabs.parse

/** Raw stabs path spellings, before any Ghidra normalisation — gcc mixes separators and drive letters. */

/** Names its own root: a leading separator, or a drive letter (`c:/…`, `E:\…`). Nothing anchors it. */
val String.isRootedPath get() = startsWith('/') || startsWith('\\') || segments.firstOrNull()?.isDriveLetter == true

/** Path segments, both separators, empties dropped: `E:\work\/x.h` → `[E:, work, x.h]`. */
val String.segments get() = split('/', '\\').filter { it.isNotEmpty() }

val String.isDriveLetter get() = length == 2 && this[0].isLetter() && this[1] == ':'

val String.isDirectory get() = endsWith('/')

/** [path] without its last segment, empty when it has none. Both separators, as stabs mixes them. */
fun String.dropLastSegment() = maxOf(lastIndexOf('/'), lastIndexOf('\\')).takeIf { it > 0 }?.let { take(it) }.orEmpty()

val String.isExplicitlyRelative get() = startsWith("./") ||
    startsWith("../") ||
    startsWith(""".\""") ||
    startsWith("""..\""")
