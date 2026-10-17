package ghistabs.harvest

import ghidra.app.util.bin.FileBytesProvider
import ghidra.app.util.bin.format.pe.PortableExecutable
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol
import ghidra.app.util.opinion.PeLoader
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program

/**
 * The external COFF symbols of a PE that Ghidra's loader drops: `AbstractPeDebugLoader.processDebugCoffSymbol`
 * skips every symbol whose value is 0, which is any that heads its section (`__ZN5Shape5countE` at the start of
 * `.bss` on `hello_gcc323_fullstabs.exe`). Read from the file's own symbol table; empty for anything but a PE.
 */
internal fun Program.peSectionStartSymbols(): Map<String, Address> {
    if (executableFormat != PeLoader.PE_NAME) return emptyMap()
    val bytes = memory.allFileBytes.firstOrNull() ?: return emptyMap()
    val header = runCatching {
        PortableExecutable(FileBytesProvider(bytes), SectionLayout.FILE).ntHeader.fileHeader
    }.getOrNull() ?: return emptyMap()
    val found = mutableMapOf<String, Address>()
    for (sym in header.symbols.orEmpty()) {
        if (sym.value != 0 || sym.sectionNumber <= 0) continue
        if (sym.storageClass != DebugCOFFSymbol.IMAGE_SYM_CLASS_EXTERNAL.toInt()) continue
        val section = header.getSectionHeader(sym.sectionNumber - 1) ?: continue
        found.putIfAbsent(sym.name ?: continue, imageBase.add(Integer.toUnsignedLong(section.virtualAddress)))
    }
    return found
}
