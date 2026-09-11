package ghistabs.harvest

import ghidra.app.util.bin.format.unixaout.UnixAoutHeader
import ghidra.program.model.listing.Program
import ghistabs.byteProvider

/** sun4's `TARGET_PAGE_SIZE`, which is also its `TEXT_START_ADDR` (binutils `include/aout/sun4.h`). */
private const val SUN4_PAGE = 0x2000L

/**
 * How far below its link-time addresses a paged SPARC a.out was loaded, or 0.
 *
 * SunOS maps a ZMAGIC text segment one page up, because location 0 must stay unreachable, and the
 * header is mapped as the start of that segment. Ghidra 12.1.2's `UnixAoutHeader.determineTextAddr`
 * applies that to SPARC NMAGIC but not to SPARC ZMAGIC, so `graphcnv.SUN4` loads a page below every
 * address its stabs and its symbol table name.
 *
 * Reads the header rather than [UnixAoutHeader.getTextAddr], which is the value in question. An
 * entry point below the page is the shared-library kludge `sun4.h` documents, and does start at 0.
 * Zero once Ghidra bases the segment correctly, so this retires itself rather than double-count.
 */
fun aoutTextBaseFixup(program: Program): Long {
    val text = program.memory.getBlock(".text")?.takeIf { it.isInitialized } ?: return 0L
    val header = runCatching { UnixAoutHeader(text.byteProvider, !program.memory.isBigEndian) }
        .getOrNull()
        ?.takeIf { it.isValid } ?: return 0L
    val paged = header.executableType == UnixAoutHeader.AoutType.ZMAGIC &&
        header.languageSpec.startsWith("sparc") &&
        header.entryPoint >= SUN4_PAGE
    return if (paged) text.start.offset - SUN4_PAGE else 0L
}
