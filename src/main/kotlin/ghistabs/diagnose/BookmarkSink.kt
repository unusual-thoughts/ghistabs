package ghistabs.diagnose

import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program

/**
 * Facade over BookmarkManager + MessageLog. Diagnostics with no useful
 * address go to the log only; diagnostics at intrinsically-meaningful
 * addresses (function entry, data, vtable) get a bookmark too.
 *
 * All log/bookmark messages are prefixed `[Stabs] <category>: <message>`
 * for filtering.
 *
 * Tag→counter auto-bump contract: Every log(category, ...) and bookmark(category, ...)
 * call also calls diagnostics.inc(category) to maintain consistency between
 * sink output and counter state. This enables Phase 8's regression harness to
 * read counters directly from StabsDiagnostics instead of re-parsing the log.
 */
class BookmarkSink(
    private val program: Program,
    private val parent: DiagnosticSink,
    private var diagnostics: StabsDiagnostics? = null,
) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?) {
        diagnostics?.inc(category)
        if (address != null) {
            program.bookmarkManager.setBookmark(
                address,
                BookmarkType.WARNING,
                "Stabs:$category",
                "[Stabs][${level.name}] $category: $message",
            )
        }
        parent.log(category, message, level, address)
    }
}
