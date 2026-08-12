package ghistabs.source

import java.io.File

/**
 * One [DeclaratorIndex] per local file per run.
 *
 * Keyed by modification time as well as path, so a file edited between renders in a long-lived
 * Ghidra session is re-read rather than answered from a stale scan.
 */
class SourceIndexes(private val compiledOut: (File) -> Set<Int> = { emptySet() }) {
    private val indexes = mutableMapOf<Pair<String, Long>, DeclaratorIndex>()

    operator fun get(file: File): DeclaratorIndex =
        indexes.getOrPut(file.path to file.lastModified()) { DeclaratorIndex(file.readText(), compiledOut(file)) }
}
