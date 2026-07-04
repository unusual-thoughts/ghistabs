package ghistabs.render

import ghistabs.harvest.OpenFunction

// gcc emits N_SLINEs out of address order (SjLj landing pads map back near the decl),
// so min/max source line over the same-source entries — not first/last by address —
// bounds the body. `prologueLine` (lowest-address entry) is the fallback opener.
private data class RawSpan(
    val func: OpenFunction,
    val prologueAddr: Long,
    val prologueLine: Int,
    val minLine: Int,
    val end: Int,
    val sameSource: Boolean,
)

data class FuncRange(val func: OpenFunction, val startLine: Int, val endLine: Int) {
    // Single-line range = a self-closing decl (header-inline out-of-line copies,
    // synthetic init wrappers): no body to bracket.
    val isSingleLine get() = startLine == endLine
}

/** Function brackets for one source file, derived purely from N_SLINE entries. */
class FunctionSpans(val ranges: List<FuncRange>) {
    val startLines = ranges.map { it.startLine }.toSet()

    val closeLineByFunc: Map<OpenFunction, Int> = ranges.mapNotNull { r ->
        when {
            r.isSingleLine -> null
            (r.endLine + 1) in startLines -> r.func to r.endLine
            else -> r.func to r.endLine + 1
        }
    }.toMap()

    private val spans = ranges.map { it.startLine..(closeLineByFunc[it.func] ?: it.startLine) }

    fun closeLine(func: OpenFunction) = closeLineByFunc[func]
    fun inFunction(line: Int) = spans.any { line in it }

    val maxLine = sequenceOf(
        closeLineByFunc.values.maxOrNull() ?: 0,
        ranges.maxOfOrNull { it.startLine } ?: 0,
        ranges.maxOfOrNull { it.endLine } ?: 0,
    ).max()

    companion object {
        /**
         * Pull each opener up to its lowest same-source line, but only while it stays
         * clear of every earlier function — a min-line below a prior function's end is
         * gcc cross-attribution, so there fall back to the prologue line.
         */
        fun of(
            rawFuncs: List<OpenFunction>,
            source: String,
            canon: (String) -> String = { it },
        ): FunctionSpans {
            var prevEnd = Int.MIN_VALUE
            val rawRanges = rawFuncs
                .mapNotNull { it.rawSpan(source, canon) }
                .sortedBy { it.prologueAddr }
                .map { s ->
                    val start = if (s.sameSource && s.minLine > prevEnd) s.minLine else s.prologueLine
                    prevEnd = maxOf(prevEnd, s.end)
                    FuncRange(s.func, start, s.end)
                }
                .sortedBy { it.startLine }

            // Drop ranges strictly contained inside another's — header method-decl
            // fragments overlapping a real method's range.
            val ranges = rawRanges.filter { r ->
                rawRanges.none { other ->
                    other !== r &&
                        other.startLine <= r.startLine &&
                        r.endLine <= other.endLine &&
                        (other.startLine < r.startLine || r.endLine < other.endLine)
                }
            }
            return FunctionSpans(ranges)
        }

        // Prefer entries tagged with `source`; with none — and not a synthetic init
        // wrapper — fall back to all entries (out-of-line copies of header methods).
        private fun OpenFunction.rawSpan(source: String, canon: (String) -> String): RawSpan? {
            val sameSource = lineEntries.filter { canon(it.source) == source }
            val inside = sameSource.ifEmpty { if (isSyntheticInit) emptyList() else lineEntries }
            if (inside.isEmpty()) return null
            val sortedByAddr = inside.sortedBy { it.addr.offset }
            val hasSame = sameSource.isNotEmpty()
            return RawSpan(
                func = this,
                prologueAddr = addr.offset,
                prologueLine = sortedByAddr.first().line,
                minLine = if (hasSame) sameSource.minOf { it.line } else sortedByAddr.first().line,
                end = if (hasSame) sameSource.maxOf { it.line } else sortedByAddr.last().line,
                sameSource = hasSame,
            )
        }
    }
}
