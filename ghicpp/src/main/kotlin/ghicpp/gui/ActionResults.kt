package ghicpp.gui

import ghicpp.dissect.FieldRetype
import ghicpp.hierarchy.SlotRenames

// What the class actions that rework the program say they did, in the dialog that ends each.

private const val MAX_LINES = 40

/** [lines] after [head], indented, at most [MAX_LINES] of them, then how many more there were. */
private fun StringBuilder.appendList(head: String, lines: List<String>) {
    append(head)
    lines.take(MAX_LINES).forEach { append("\n  ").append(it) }
    if (lines.size > MAX_LINES) append("\n  … and ${lines.size - MAX_LINES} more")
}

/** Update Field Types: each class's fields it typed, by offset, from what type to what. */
internal fun fieldTypesResult(retyped: List<Pair<String, List<FieldRetype>>>, cancelled: Boolean): String =
    buildString {
        val lines = retyped.flatMap { (cls, fields) ->
            fields.sortedBy { it.offset }.map { f ->
                "$cls +0x%x %s: %s".format(f.offset, f.name, f.was?.let { "$it → ${f.type}" } ?: f.type)
            }
        }
        if (lines.isEmpty()) append("No field changed type.") else appendList("Typed ${lines.size} field(s):", lines)
        if (cancelled) append("\n\nCancelled: the fields typed before then keep their types.")
    }

/** Apply Slot Names to Vftables: how many slots it named, and those that kept their old names and why. */
internal fun slotNamesResult(done: SlotRenames): String = buildString {
    append(if (done.fields == 0) "No vftable slot was renamed." else "Named ${done.fields} vftable slot(s).")
    if (done.skipped.isNotEmpty()) appendList("\n\nKept their old names:", done.skipped)
}

/** Apply Signature to Vftables: how many slot definitions each function's signature went into. */
internal fun signaturesResult(applied: List<Pair<String, Int>>): String = buildString {
    val total = applied.sumOf { it.second }
    append("Applied ${applied.size} signature(s) to $total vftable slot definition(s)")
    appendList(":", applied.map { (f, n) -> "$f: $n definition(s)" })
}
