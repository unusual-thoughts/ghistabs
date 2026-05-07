package ghistabs.importer

import ghidra.app.util.importer.MessageLog
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
 */
class BookmarkSink(
    private val program: Program,
    private val messageLog: MessageLog,
) {
    fun bookmark(
        category: String,
        addr: Address,
        message: String,
    ) {
        program.bookmarkManager.setBookmark(
            addr,
            BookmarkType.WARNING,
            "Stabs:$category",
            "[Stabs] $category: $message",
        )
        messageLog.appendMsg("[Stabs] $category at $addr: $message")
    }

    fun log(
        category: String,
        message: String,
    ) {
        messageLog.appendMsg("[Stabs] $category: $message")
    }
}
