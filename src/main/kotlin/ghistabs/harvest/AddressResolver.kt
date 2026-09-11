package ghistabs.harvest

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.opinion.ElfLoader
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghistabs.baseStackParamOffset
import ghistabs.byteProvider
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.*
import ghistabs.plus

/**
 * Turns the numbers a stab carries into program addresses. One resolver serves the whole run, so the
 * harvest, the materializer and the render place things identically.
 *
 * A stab's `n_value` is a bare integer whose meaning belongs to the record holding it: an absolute
 * address, an offset from the enclosing function ([stabAddress]), or no address at all for a local
 * living in a register or a frame slot. A global static is the exception that is not a number at
 * all: its address comes from the linker symbol of that name ([resolve]).
 */
interface AddressResolver {
    fun buildAddress(offset: Long): Address

    /** Where the link-time symbol [name] ended up; the first bearer where several carry it. */
    fun resolve(name: String): Address?

    /** Inclusive end of the memory block holding [addr] — where a range with no successor stops. */
    fun blockEnd(addr: Address): Address? = null
    fun forSymbol(sym: Symbol<*>): Address? = when (val decl = sym.body) {
        is SymbolDecl.Static if decl.scope == StaticScope.GLOBAL -> resolve(decl.name)
        is SymbolDecl.Function, is SymbolDecl.Static -> buildAddress(sym.rawValue)
        is SymbolDecl.Constant, is SymbolDecl.NamedType, is SymbolDecl.Local, is SymbolDecl.Param -> null
    }

    /**
     * Resolve a stab `n_value` that may be function-relative: block scopes and line numbers in
     * stabs-in-sections are offsets from [funcStart] (a genuine offset stays below it; an already
     * absolute value doesn't). Pass a null [funcStart] for records that are always absolute. Tallies
     * which branch it took on [sink] (`stab-value-func-relative` vs `stab-value-absolute`).
     */
    fun stabAddress(value: Long, funcStart: Address?, sink: DiagnosticSink = DummySink) =
        if (funcStart != null && value < funcStart.offset) {
            sink.debug("stab-value-func-relative")
            funcStart + value
        } else {
            sink.debug("stab-value-absolute")
            buildAddress(value)
        }
}

/**
 * Address resolver that searches program symbols and builds addresses in the default program address space.
 */
class ProgramAddressResolver(private val program: Program, private val sink: DiagnosticSink = DummySink) :
    AddressResolver {
    // Stab values are link-time vaddrs. Ghidra relocates a PIE/ET_DYN ELF to its load
    // base (default 0x100000) without rewriting the stabs, so every address is off by
    // (loadBase - originalBase). PE has no such property → null → no fixup. Mirrors
    // Ghidra's own DWARF address fixup (DIEContainer.setProgramBaseAddressFixup).
    private val baseFixup: Long =
        ElfLoader.getElfOriginalImageBase(program)?.let { program.imageBase.offset - it }
            ?: aoutTextBaseFixup(program)

    /**
     * The same correction for a paged a.out, where the shortfall is the loader's rather than the
     * format's. SunOS maps a ZMAGIC text segment one page up — location 0 must stay unreachable —
     * but `UnixAoutHeader.determineTextAddr` applies that to SPARC NMAGIC and not to SPARC ZMAGIC,
     * so `graphcnv.SUN4` loads a page below every address its stabs and its symbol table name. The
     * file says so itself: ZMAGIC maps the 32-byte exec header as the start of the text segment, so
     * it is readable at `.text`, and `a_entry` (0x2020) sits one header past the page.
     *
     * Zero once Ghidra bases the segment correctly, so this retires itself rather than double-count.
     */
    private companion object {
        /** `struct exec` words read to reach `a_entry`. */
        const val EXEC_WORDS = 6

        /** 0413. */
        const val ZMAGIC = 0x10BL

        /** binutils `include/aout/aout64.h`. */
        const val M_SPARC = 3L

        /** sun4's `TARGET_PAGE_SIZE`, which is also its `TEXT_START_ADDR`. */
        const val SUN4_PAGE = 0x2000L
    }

    private fun aoutTextBaseFixup(program: Program): Long {
        val text = program.memory.getBlock(".text")?.takeIf { it.isInitialized } ?: return 0L
        // struct exec: a_info, a_text, a_data, a_bss, a_syms, a_entry, ...
        val exec = runCatching {
            val reader = BinaryReader(text.byteProvider, !program.memory.isBigEndian)
            List(EXEC_WORDS) { reader.readNextUnsignedInt() }
        }.getOrNull() ?: return 0L
        val info = exec.first()
        val entry = exec.last()
        val magic = info and 0xFFFFL
        val machine = (info shr 16) and 0xFFL
        // binutils include/aout/sun4.h: ZMAGIC on sun4 starts at one page, except the shared-library
        // kludge where `a_entry` falls below it.
        if (magic != ZMAGIC || machine != M_SPARC || entry < SUN4_PAGE) return 0L
        return text.start.offset - SUN4_PAGE
    }

    override fun buildAddress(offset: Long): Address = program.addressFactory.defaultAddressSpace.getAddress(offset) +
        // A negative fixup only applies to values large enough to be vaddrs: callers also pass
        // frame offsets and register numbers through here, and those would underflow the space.
        baseFixup.takeIf { offset + it >= 0 }.orEmptyFixup()

    private fun Long?.orEmptyFixup() = this ?: 0L

    /**
     * a.out link-time symbols straight from the file, which outrank Ghidra's for this format:
     * `UnixAoutProgramLoader` places them at `dataBlock.getStart().add(symbol.value)` although
     * `n_value` is already image-relative, so its symbols sit one text-segment too high (verified on
     * `hello_aout_gcc295.o`: `global_total` has `n_value=0x74` with `.data` at `0x64`, and Ghidra
     * reports `0xd8`). Empty for ELF/PE, where Ghidra's symbol table is the only source.
     */
    private val linkSymbols: Map<String, Long> by lazy { StabReader.linkSymbolsOf(program) }

    /**
     * Resolve [name]: link table → symbol table, each tried bare then `_`-prefixed (MinGW/PE cdecl and
     * SunOS both prefix — `Foo`→`_Foo`, `_ZTI4Foo`→`__ZTI4Foo`). The link table has to try both as
     * well, or an underscoring a.out drops through to Ghidra's symbols — the very ones [linkSymbols]
     * exists to overrule (1084 globals on `graphcnv.SUN4`, every one landing outside the image).
     * Several symbols carrying one name is common — 169 on one PE fixture, 1991 on locale_test — and
     * nothing here can tell them apart, so the first stands.
     *
     * Memory addresses only: `getSymbols(String)` answers with symbols of every kind, and a function's
     * locals and parameters live in Ghidra's `VARIABLE` space rather than the image. A name the binary
     * genuinely lacks otherwise resolves onto some unrelated variable that happens to share it — four
     * CUs on `graphcnv.SUN4` declare `ax:G(0,6)`, nothing links it, and `wowed.c`'s own stack local
     * `ax` answered for it at `VARIABLE:00000100`.
     */
    override fun resolve(name: String): Address? {
        (linkSymbols[name] ?: linkSymbols["_$name"])?.let { return buildAddress(it) }
        val candidates = (
            program.symbolTable.getSymbols(name).map { it.address } +
                program.symbolTable.getSymbols("_$name").map { it.address }
            ).filter { it.isMemoryAddress }
        if (candidates.size > 1) sink.debug("resolve-ambiguous", name)
        return candidates.firstOrNull()
    }

    override fun blockEnd(addr: Address) = program.memory.getBlock(addr)?.end

    /**
     * Where gcc put this local, as an address the decompiler indexes storage by: the register itself, or
     * the frame slot at Ghidra's origin rather than gcc's frame-pointer-relative one. Null for anything
     * that is neither — and for the dbx register numbers [ghistabs.parse.dbxRegisterName] declines to map (the x87
     * stack), which is the same set the importer skips.
     */
    override fun forSymbol(sym: Symbol<*>) = when (sym.location) {
        VariableLocation.REGISTER -> program.dbxRegisterName(sym.rawValue.toInt())
            ?.let { program.getRegister(it)?.address }

        VariableLocation.STACK -> program.addressFactory.stackSpace.getAddress(
            sym.rawValue - program.baseStackParamOffset,
        )

        null -> super.forSymbol(sym)
    }
}
