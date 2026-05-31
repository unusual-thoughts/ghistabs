package ghistabs.importer

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program
import ghistabs.diag.DiagnosticSink
import ghistabs.diag.StabsDiagnostics

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
    private val messageLog: MessageLog,
    private var diagnostics: StabsDiagnostics? = null,
) : DiagnosticSink {
    fun bookmark(category: String, addr: Address, message: String) {
        diagnostics?.inc(category)
        program.bookmarkManager.setBookmark(
            addr,
            BookmarkType.WARNING,
            "Stabs:$category",
            "[Stabs] $category: $message",
        )
        messageLog.appendMsg("[Stabs] $category at $addr: $message")
    }

    override fun log(category: String, message: String) {
        diagnostics?.inc(category)
        messageLog.appendMsg("[Stabs] $category: $message")
    }
}
