package ghistabs.source

import ghidra.app.util.cparser.CPP.PreProcessor
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
         * Preprocess [unit] with [includePaths], or null when the environment is not complete
         * enough to be believed — a gcc *source* tarball has no generated `bits/c++config.h`, and a
         * conditional decided on a macro that was never defined is worse than not asking.
         */
        fun of(unit: File, includePaths: List<File>, sink: DiagnosticSink): Preprocessed? {
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
                sink.warn(
                    "source-preprocess-incomplete",
                    "${unit.name}: ${missing.size} includes unresolved, reading raw — ${missing.first().trim()}",
                    count = missing.size.toLong(),
                )
                return null
            }
            return Preprocessed(droppedLines(out.toString()))
        }

        private const val MISSING_INCLUDE = "No path to #include"
        private const val DROPPED = "///-"
        private val MARKER = Regex("""#line \d+: "(.*)"""")

        /**
         * Walk the stream, matching each echoed dropped line forward through the file it came from.
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
            for (line in stream.lineSequence().map { it.trim() }) {
                val marker = MARKER.matchEntire(line)
                if (marker != null) {
                    path = File(marker.groupValues[1]).takeIf { it.isFile }?.canonicalPath
                        ?.also { texts.getOrPut(it) { File(it).readLines() } }
                    continue
                }
                val file = path?.takeIf { line.startsWith(DROPPED) } ?: continue
                val text = line.removePrefix(DROPPED).trim().ifEmpty { continue }
                val lines = texts.getValue(file)
                val at = ((cursors[file] ?: 0) until lines.size)
                    .firstOrNull { lines[it].trim() == text } ?: continue
                dropped.getOrPut(file) { mutableSetOf() } += at + 1
                cursors[file] = at + 1
            }
            return dropped
        }
    }
}
