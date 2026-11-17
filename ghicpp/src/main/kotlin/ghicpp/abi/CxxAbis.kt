package ghicpp.abi

import ghicpp.*
import ghicpp.abi.gcc2.Gcc2
import ghicpp.abi.gcc2.Gcc2Plain
import ghicpp.abi.gcc2.Gcc2Thunks
import ghicpp.abi.generic.PlainVtables
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.itanium.SpecialName
import ghicpp.abi.msvc.Msvc
import ghicpp.abi.msvc.msvcSubobjectOffset
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolTable
import ghidrakt.*

// Which ABI a symbol, a table or a binary is of, asked of every ABI this package implements.

/** The ABI whose vtable symbol [symbolName] is, a gcc 2.x secondary's included; null if none. */
fun CxxAbi.Companion.ofVtableSymbol(symbolName: String): CxxAbi? = when {
    Gcc2Thunks.looksLikeVtable(symbolName) -> Gcc2Thunks
    Gcc2Plain.looksLikeVtable(symbolName) -> Gcc2Plain
    Itanium.looksLikeVtable(symbolName) -> Itanium
    Msvc.looksLikeVtable(symbolName) -> Msvc
    else -> null
}

/**
 * The ABI whose record the table at the address point [vftable] is ([CxxAbi.ownsVftable]); [PlainVtables] for a
 * table no record names, such as one seeded off a pointer table.
 */
fun CxxAbi.Companion.ofVftable(program: Program, vftable: Address): CxxAbi =
    listOf(Gcc2Thunks, Gcc2Plain, Msvc, Itanium).firstOrNull { it.ownsVftable(program, vftable) }
        ?: PlainVtables

/** Data the compiler generated for a class, a vtable or typeinfo, rather than any the source declares. */
fun CxxAbi.Companion.isGeneratedData(name: String) =
    Itanium.isGeneratedData(name) || ofVtableSymbol(name) != null || Gcc2.isTypeinfoName(name)

/** A `this`-adjusting thunk, by its gcc 2.x or Itanium symbol. */
fun CxxAbi.Companion.looksLikeThunk(name: String) =
    Gcc2.looksLikeThunk(name) || Itanium.specialName(name) == SpecialName.THUNK

/** Every gcc ABI's symbols for [className]'s vtable, Itanium first. */
fun CxxAbi.Companion.vtableCandidates(className: String) = buildList {
    addAll(Itanium.vtableCandidates(className))
    addAll(Gcc2Plain.vtableCandidates(className))
    addAll(Gcc2Thunks.vtableCandidates(className))
}

/**
 * The ABI a binary was built with: that of the first primary vtable symbol, even an undefined one,
 * else the one most mangled names are in. Null for a binary with neither, such as a C one.
 */
fun CxxAbi.Companion.prevailing(symbolNames: Sequence<String>): CxxAbi? {
    val byMember = mutableMapOf<CxxAbi, Int>()
    for (name in symbolNames) {
        ofVtableSymbol(name)?.takeIf { it.isPrimaryVtable(name) }?.let { return it }
        mangledBy(name)?.let { byMember[it] = byMember.getOrDefault(it, 0) + 1 }
    }
    return byMember.maxByOrNull { it.value }?.key
}

/** [prevailing] over a program's symbols. */
fun SymbolTable.prevailingAbi(): CxxAbi? {
    // A SymbolIterator is an Iterator and an Iterable, and `asSequence` is on both.
    val symbols: Iterator<Symbol> = symbolIterator
    return CxxAbi.prevailing(symbols.asSequence().map { it.name })
}

/** The constructor or destructor [mangled] names, under whichever ABI mangled it. */
fun CxxAbi.Companion.structorOf(mangled: String): Structor? =
    listOf(Msvc, Gcc2Thunks, Itanium).firstNotNullOfOrNull { it.structorOf(mangled) }

/** The ABI that mangled [name]; [Gcc2Thunks] for gcc 2.x, whose two ABIs mangle alike. */
fun CxxAbi.Companion.mangledBy(name: String): CxxAbi? = when {
    Itanium.isProbablyMangled(name) -> Itanium
    Gcc2.isProbablyMangled(name) -> Gcc2Thunks
    Msvc.isProbablyMangled(name) -> Msvc
    else -> null
}

/**
 * Whether [sym], one of [abi]'s table symbols, is its class's own table: by its name, else, for one of an MSVC
 * class's several tables, by its complete object locator, which gives its own offset 0.
 */
fun isPrimaryTableSymbol(sym: Symbol, abi: CxxAbi): Boolean =
    abi.isPrimaryVtable(sym.name) || (abi == Msvc && sym.program.msvcSubobjectOffset(sym.address) == 0)

/** The class whose own vtable [sym] is, demangled, and its ABI; null for a secondary or any other symbol. */
fun primaryVtableOf(sym: Symbol): Pair<String, CxxAbi>? = CxxAbi.ofVtableSymbol(sym.name)
    ?.takeIf { isPrimaryTableSymbol(sym, it) }
    ?.let { abi -> Demangler.of(sym.name)?.let(abi::demangledVtableClass)?.let { it to abi } }
