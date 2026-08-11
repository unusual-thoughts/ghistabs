package ghistabs.render

import ghistabs.harvest.Func
import org.jetbrains.annotations.TestOnly

// gcc emits N_SLINEs out of address order (SjLj landing pads map back near the decl),
// so min/max source line over the same-source entries — not first/last by address —
// bounds the body. `prologueLine` (lowest-address entry) is the fallback opener.
private data class RawSpan(
    val func: Func,
    val prologueAddr: Long,
    val prologueLine: Int,
    val minLine: Int,
    val end: Int,
    val sameSource: Boolean,
) {
    fun toRange(prevEnd: Int) = FuncRange(func, if (sameSource && minLine > prevEnd) minLine else prologueLine, end)
}

fun <T : Comparable<T>> ClosedRange<T>.includes(other: ClosedRange<T>) =
    contains(other.start) && contains(other.endInclusive)
fun <T : Comparable<T>> ClosedRange<T>.includesStrict(other: ClosedRange<T>) =
    includes(other) && (start != other.start || endInclusive != other.endInclusive)

data class FuncRange(val func: Func, @get:TestOnly val lines: IntRange) : ClosedRange<Int> by lines {
    constructor(func: Func, start: Int, end: Int) : this(func, minOf(start, end)..maxOf(start, end))

    // Single-line range = a self-closing decl (header-inline out-of-line copies,
    // synthetic init wrappers): no body to bracket.
    val isSingleLine get() = lines.first == lines.last
    val nextLine get() = lines.last + 1
}

/** Function brackets for one source file, derived purely from N_SLINE entries. */
class FunctionSpans(val ranges: List<FuncRange>) {
    private val startLines = ranges.map { it.start }.toSet()

    val FuncRange.closeLine get() = when {
        isSingleLine -> null
        nextLine in startLines -> endInclusive
        else -> nextLine
    }

    val FuncRange.span get() = start..(closeLine ?: start)

    val FuncRange.interior get() = when {
        isSingleLine -> null
        nextLine in startLines -> start + 1..<endInclusive
        else -> start + 1..endInclusive
    }

    private val spans = ranges.map { it.span }

    fun inFunction(line: Int) = spans.any { line in it }

    private val interiors = ranges.mapNotNull { it.interior }

    /** Is [line] between some function's braces — where no file-scope declaration can go? */
    fun insideBody(line: Int) = interiors.any { line in it }

    /**
     * The last row content anchored at [line] may take. A claim slides downward when the row it asked
     * for is held, and what it slides *through* was bounded by nothing: an inlined stretch anchored at
     * xdvimage.cpp L30 landed at row 47, inside `has_slt`. Every row below an opener belongs to that
     * function, so the row before the next one is as far as anything may reach. Null where no
     * function follows — the canvas end is then the only bound, which is [Claim.limit]'s own default.
     */
    fun barrier(line: Int) = ranges.filter { it.start > line }.minOfOrNull { it.start - 1 }

    val maxLine = ranges.maxOfOrNull { it.span.last } ?: 0

    companion object {
        /**
         * Pull each opener up to its lowest same-source line, but only while it stays
         * clear of every earlier function — a min-line below a prior function's end is
         * gcc cross-attribution, so there fall back to the prologue line.
         */
        fun of(rawFuncs: List<Func>, source: String): FunctionSpans {
            val rawRanges = buildList {
                var prevEnd = Int.MIN_VALUE
                for (s in rawFuncs.mapNotNull { it.rawSpan(source) }.sortedBy { it.prologueAddr }) {
                    add(s.toRange(prevEnd))
                    prevEnd = maxOf(prevEnd, s.end)
                }
            }.sortedBy { it.start }

            // Drop ranges strictly contained inside another's — header method-decl
            // fragments overlapping a real method's range.
            val ranges = rawRanges.filter { r ->
                rawRanges.none { other -> other !== r && other.includesStrict(r) }
            }
            return FunctionSpans(ranges)
        }

        // Prefer entries tagged with `source`; with none — and not a synthetic init
        // wrapper — fall back to all entries (out-of-line copies of header methods).
        private fun Func.rawSpan(source: String): RawSpan? {
            val sameSource = lineEntries.filter { it.source == source }
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
