package ghistabs.parse

import ghistabs.index.*

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

/**
 * A source spelling written relative to its compilation directory, resolved against it —
 * `../../../include/directory/header.h` compiled in `E:/dev/code/projects/someproject/dir/` is
 * `E:/dev/code/include/directory/header.h`. Unresolvable (more `..` than the directory has
 * segments) or [directory]-less spellings are returned unchanged.
 *
 * Only a spelling that *says* it is relative — opens with `./` or `../` — is resolved. gcc writes a
 * bare filename relative to the CU too, but resolving those would break [ghistabs.harvest.foldSourcePaths]: one
 * physical header staged into two places is spelled bare by the CU that owns it and by full path
 * everywhere else, and resolving the bare one gives the two spellings different parent directories.
 * `header.h` would split into `include/directory/header.h` and `projects/someproject/dir/header.h`.
 */
fun String.resolveAgainstDirectory(directory: String?): String {
    if (directory == null || !isExplicitlyRelative) return this
    var base = directory.trimEnd('/', '\\')
    val rest = mutableListOf<String>()
    // A split and nothing more: this runs before any identity exists, on a spelling that says it is
    // relative — so there is no drive letter to strip and no `..` yet resolved.
    for (segment in segments) {
        when (segment) {
            "." -> {}
            ".." -> base = base.dropLastSegment().ifEmpty { return this }
            else -> rest += segment
        }
    }
    return (listOf(base) + rest).joinToString("/")
}
