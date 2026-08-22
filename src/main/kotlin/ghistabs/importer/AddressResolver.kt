package ghistabs.importer

import ghidra.app.util.opinion.ElfLoader
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghistabs.baseStackParamOffset
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.harvest.Symbol
import ghistabs.parse.*
import ghistabs.plus

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
        ElfLoader.getElfOriginalImageBase(program)?.let { program.imageBase.offset - it } ?: 0L

    override fun buildAddress(offset: Long): Address =
        program.addressFactory.defaultAddressSpace.getAddress(offset) + baseFixup

    /**
     * a.out link-time symbols straight from the file, which outrank Ghidra's for this format:
     * `UnixAoutProgramLoader` places them at `dataBlock.getStart().add(symbol.value)` although
     * `n_value` is already image-relative, so its symbols sit one text-segment too high (verified on
     * `hello_aout_gcc295.o`: `global_total` has `n_value=0x74` with `.data` at `0x64`, and Ghidra
     * reports `0xd8`). Empty for ELF/PE, where Ghidra's symbol table is the only source.
     */
    private val linkSymbols: Map<String, Long> by lazy { StabReader.linkSymbolsOf(program) }

    /**
     * Resolve [name]: symbol table → `_<name>` (MinGW/PE cdecl underscore prefix —
     * `Foo`→`_Foo`, `_ZTI4Foo`→`__ZTI4Foo`). Several symbols carrying one name is common — 169 on
     * one PE fixture, 1991 on locale_test — and nothing here can tell them apart, so the first stands.
     */
    override fun resolve(name: String): Address? {
        linkSymbols[name]?.let { return buildAddress(it) }
        val candidates = (program.symbolTable.getSymbols(name) + program.symbolTable.getSymbols("_$name"))
            .map { it.address }
        if (candidates.size > 1) sink.debug("resolve-ambiguous", name)
        return candidates.firstOrNull()
    }

    override fun blockEnd(addr: Address) = program.memory.getBlock(addr)?.end

    /**
     * Where gcc put this local, as an address the decompiler indexes storage by: the register itself, or
     * the frame slot at Ghidra's origin rather than gcc's frame-pointer-relative one. Null for anything
     * that is neither — and for the dbx register numbers [dbxRegisterName] declines to map (the x87
     * stack), which is the same set the importer skips.
     */
    override fun forSymbol(sym: Symbol<*>) = when (sym.location) {
        VariableLocation.REGISTER -> dbxRegisterName(program.defaultPointerSize, sym.rawValue.toInt())
            ?.let { program.getRegister(it)?.address }

        VariableLocation.STACK -> program.addressFactory.stackSpace.getAddress(
            sym.rawValue - program.baseStackParamOffset,
        )

        null -> super.forSymbol(sym)
    }
}
