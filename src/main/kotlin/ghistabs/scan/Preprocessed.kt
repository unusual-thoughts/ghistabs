package ghistabs.scan

import ghidra.app.util.cparser.CPP.PreProcessor
import ghistabs.ECHOES_DROPPED_LINES
import ghistabs.diagnose.DiagnosticSink
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Which lines a compilation dropped, per file, in each file's own line numbers — the one thing raw
 * text cannot say. Without it both arms of `stl_threads.h`'s `__STL_THREADS` are indexed, which a
 * line lookup survives (a line is in one arm or the other) but a mismatched brace does not.
 *
 * The platform preprocesses: [PreProcessor] has no grammar to choke on and resolves `#include`s the
 * way the compiler did. What it does not give is *positions*. Measured on its own output: block
 * comments are removed rather than blanked, so the text has slid by several lines before the first
 * declaration of a licence-headed header, and every emitted line is macro-expanded, so it cannot be
 * matched back either. Its `#line n: "file"` markers count what it printed, not what it read.
 *
 * The `///- <text>` lines are the exception, and they are the ones that matter here: a dropped line
 * is echoed **verbatim**, unexpanded, in order. Matching that text forward through the file recovers
 * its line, and every number stays the file's own.
 */
class Preprocessed private constructor(private val dropped: Map<String, Set<Int>>) {
    operator fun get(file: File): Set<Int> = dropped[file.canonicalPath].orEmpty()

    companion object {
        /**
         * The dropped lines of every file [units] reach, for [SourceIndexes]. A unit whose
         * environment cannot be believed contributes nothing rather than a guess, so with no local
         * sources — or no complete one — this answers empty and the scan reads the raw text, which
         * is what it did before any of this existed.
         *
         * Where two units compiled one header differently, the union is dropped and the header keeps
         * neither arm: balance over recall. Both arms present is the mismatched brace this exists to
         * prevent, while both arms gone costs the definitions in a header whose two compiles already
         * disagree about which of them exists.
         *
         * Preprocessed on first use, not per query: one run covers every header that unit included.
         */
        fun lines(units: List<File>, includePaths: List<File>, sink: DiagnosticSink): (File) -> Set<Int> {
            val all by lazy { units.mapNotNull { of(it, includePaths, sink) } }
            return { file -> all.flatMapTo(mutableSetOf()) { it[file] } }
        }

        /**
         * Preprocess [unit] with [includePaths], or null when the environment is not complete
         * enough to be believed — a gcc *source* tarball has no generated `bits/c++config.h`, and a
         * conditional decided on a macro that was never defined is worse than not asking.
         */
        fun of(unit: File, includePaths: List<File>, sink: DiagnosticSink): Preprocessed? {
            // The `///-` echo of a dropped line is a CPP-grammar change in 11.3, not an API one.
            if (!ECHOES_DROPPED_LINES) {
                sink.warn("source-preprocess-unsupported", "${unit.name}: Ghidra 11.3+ echoes dropped lines")
                return null
            }
            val out = ByteArrayOutputStream()
            val pp = runCatching {
                PreProcessor().apply {
                    addIncludePaths(includePaths.map { it.path }.toTypedArray())
                    setOutputStream(out)
                    parse(unit.path)
                }
            }.getOrElse {
                sink.warn("source-preprocess-failed", "${unit.name}: ${it.message}")
                return null
            }
            val missing = pp.parseMessages.lines().filter { MISSING_INCLUDE in it }
            if (missing.isNotEmpty()) {
                missing.forEach { sink.warn("source-preprocess-incomplete", "${unit.name}: ${it.trim()}") }
                return null
            }
            return Preprocessed(droppedLines(out.toString()))
        }

        private const val MISSING_INCLUDE = "No path to #include"
        private const val DROPPED = "///-"
        private val MARKER = Regex("""#line \d+: "(.*)"""")

        /**
         * Walk the stream, matching each *run* of echoed dropped lines forward through the file it
         * came from. A run is what one conditional dropped: consecutive echoes, blanks included, and
         * the `#if`/`#endif` around them are not echoed at all.
         *
         * Whole runs rather than single lines, because the first line of a block is rarely
         * distinctive: `cpp_type_traits.h`'s dropped `template<>` matched the first of the fourteen
         * earlier ones and reported L78 for a block at L139. A run of eight has to match in order.
         *
         * One cursor per file, never rewound: the markers say which file is being printed but not
         * where in it, and a `#endif` or a `}` echoed twice would otherwise match the first one
         * every time.
         */
        private fun droppedLines(stream: String): Map<String, Set<Int>> {
            val texts = mutableMapOf<String, List<String>>()
            val cursors = mutableMapOf<String, Int>()
            val dropped = mutableMapOf<String, MutableSet<Int>>()
            var path: String? = null
            var run = mutableListOf<String>()

            /** Place [run] in [path]'s text, from its cursor, and move the cursor past it. */
            fun flush() {
                val file = path?.takeIf { run.isNotEmpty() } ?: return run.clear()
                val lines = texts.getValue(file)
                val from = cursors[file] ?: 0
                val at = (from..lines.size - run.size)
                    .firstOrNull { start -> run.indices.all { lines[start + it].trim() == run[it] } }
                if (at != null) {
                    dropped.getOrPut(file) { mutableSetOf() } += (at + 1)..(at + run.size)
                    cursors[file] = at + run.size
                }
                run = mutableListOf()
            }

            for (line in stream.lineSequence().map { it.trim() }) {
                when {
                    line.startsWith(DROPPED) -> run += line.removePrefix(DROPPED).trim()
                    else -> {
                        flush()
                        MARKER.matchEntire(line)?.let { marker ->
                            path = File(marker.groupValues[1]).takeIf { it.isFile }?.canonicalPath
                                ?.also { texts.getOrPut(it) { File(it).readLines() } }
                        }
                    }
                }
            }
            flush()
            return dropped
        }
    }
}
