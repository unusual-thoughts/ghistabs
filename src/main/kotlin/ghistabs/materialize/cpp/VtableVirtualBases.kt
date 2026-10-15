package ghistabs.materialize.cpp

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.diagnose.DiagnosticSink
import ghistabs.index.LocatedType
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.cpp.abi.Itanium
import ghistabs.materialize.cpp.abi.ResolvedVtable
import ghistabs.materialize.cpp.abi.Rtti
import ghistabs.materialize.cpp.abi.VtableRecord
import ghistabs.materialize.cpp.abi.rttiOf
import ghistabs.materialize.cpp.abi.typeinfoClass
import ghistabs.materialize.cpp.abi.vtableRecord
import ghistabs.parse.leafName
import ghistabs.parse.member
import ghistabs.readAs

/**
 * The virtual bases a class's stab can't show, laid where its vtable says they are. xapasmcsr's
 * `CLexStream` derives from `basic_ifstream<char>`, which no CU defines, so its stab has no virtual
 * base for [layClasses] to lay; its typeinfo still says `basic_istream` has `basic_ios` as a virtual
 * base whose offset is 12 bytes behind the vtable's address point, and that word in `_ZTV10CLexStream`
 * is 0xc0. No CU defines `basic_ios` either, so the first base of it that one does is laid instead, where
 * `basic_ios`'s typeinfo puts it: `ios_base`, 4 bytes in, behind `basic_ios`'s own vptr.
 *
 * Itanium only: gcc 2.x fills its typeinfo at run time. A class whose stab shows a virtual base is
 * [layClasses]'s, and anything that would not fit, or would cover laid bytes, is reported and left. Runs
 * after [layClasses], so a class embedded as a base was embedded without what this lays.
 */
internal fun DataTypeRegistry.layVirtualBasesFromVtables(program: Program) {
    val symbols = RttiSymbols.of(program)
    if (symbols.vtables.isEmpty() || symbols.typeinfos.isEmpty()) return
    VtableVirtualBases(this, program, symbols).layAll()
}

/** Each class's Itanium `_ZTV` and `_ZTI`, by the qualified name they demangle to. */
private class RttiSymbols(val vtables: Map<String, Address>, val typeinfos: Map<String, Address>) {
    companion object {
        fun of(program: Program): RttiSymbols {
            val vtables = mutableMapOf<String, Address>()
            val typeinfos = mutableMapOf<String, Address>()
            for (sym in program.symbolTable.getSymbolIterator(true)) {
                ResolvedVtable.fromSymbol(sym)?.takeIf { it.abi == Itanium }
                    ?.let { vtables.putIfAbsent(it.className, it.address) }
                if (Itanium.looksLikeZti(sym.name) || sym.name == ClassNaming.TYPEINFO) {
                    sym.typeinfoClass?.let { typeinfos.putIfAbsent(it, sym.address) }
                }
            }
            return RttiSymbols(vtables, typeinfos)
        }
    }
}

private class VtableVirtualBases(val registry: DataTypeRegistry, val program: Program, val symbols: RttiSymbols) :
    DiagnosticSink by registry {
    private val reader = Rtti.Reader(program)
    private val word = Itanium.offsetToTopType(program.defaultPointerSize)

    // Any struct by name, a C++ class or not: the defined part of a virtual base needn't be one.
    private val structOf = registry.byLocation.values.mapNotNull { located ->
        (registry.dataTypeFor(located.type.id) as? Structure)?.let { located.qualifiedName() to it }
    }.toMap()
    private val byLeaf = structOf.entries.groupBy { it.key.leafName }
        .mapNotNull { (leaf, all) -> all.map { it.value }.distinct().singleOrNull()?.let { leaf to it } }
        .toMap()

    fun layAll() {
        val done = mutableSetOf<Structure>()
        for (located in registry.classesBasesFirst()) {
            if (registry.types.hasVirtualBase(located.classBody)) continue
            val struct = registry.dataTypeFor(located.type.id) as? Structure ?: continue
            if (!done.add(struct)) continue
            val record = symbols.vtables[located.qualifiedName()]
                ?.let { runCatching { program.vtableRecord(it) }.getOrNull() } ?: continue
            val vbases = program.rttiOf(record)?.let(::virtualBases).orEmpty()
            val count = registry.baseSubobjects(located.classBody) + vbases.size
            for (vbase in vbases) {
                val at = "${located.location.category}/${located.type.ghidraName}".member(vbase.className)
                lay(struct, record, vbase, at, count)
            }
        }
    }

    private fun lay(struct: Structure, record: VtableRecord, vbase: Rtti.Reader.Base, at: String, count: Int) {
        val vbaseAt = runCatching { program.readAs<Scalar>(record.addressPoint.add(vbase.offset), word) }
            .getOrNull()?.signedValue?.toInt()
        if (vbaseAt == null || vbaseAt <= 0 || vbaseAt >= struct.length) {
            return degradation("vbase-offset-unreadable", at, "vtable word at ${vbase.offset} reads $vbaseAt")
        }
        val (dt, within) = definedPart(vbase.className)
            ?: return degradation("vbase-undefined", at, "no CU defines it or a base of it")
        val offset = vbaseAt + within
        when {
            offset + dt.length > struct.length -> degradation(
                "vbase-layout-failed",
                at,
                "${dt.name} (${dt.length}b) at +$offset overruns ${struct.length}",
            )

            struct.definedComponents.any { offset < it.offset + it.length && it.offset < offset + dt.length } ->
                degradation("vbase-layout-failed", at, "${dt.name} at +$offset covers laid fields")

            else -> runCatching {
                val part = if (within == 0 && dt.name == vbase.className.leafName) {
                    ""
                } else {
                    "; only its ${dt.name} at +$within is defined"
                }
                val comment = "${vbase.access.name.lowercase()} virtual ${vbase.className} at " +
                    "+0x${vbaseAt.toString(16)}, by the vtable$part"
                struct.replaceAtOffset(offset, dt, dt.length, ClassNaming.baseFieldName(true, dt.name, count), comment)
            }.onSuccess { debug("vbase-applied-from-vtable") }
                .onFailure { degradation("vbase-layout-failed", at, it.message) }
        }
    }

    private fun structFor(className: String) = (structOf[className] ?: byLeaf[className.leafName])
        ?.takeIf { registry.dtm.contains(it) && !it.isZeroLength }

    /** [zti]'s virtual bases, its own and those of its primary chain, each with its vtable offset. */
    private fun virtualBases(zti: Address, depth: Int = 0): List<Rtti.Reader.Base> =
        reader.basesOf(zti).orEmpty().takeIf { depth < MAX_DEPTH }.orEmpty().flatMap { base ->
            when {
                base.isVirtual -> listOf(base)
                base.offset == 0L -> symbols.typeinfos[base.className]?.let { virtualBases(it, depth + 1) }.orEmpty()
                else -> emptyList()
            }
        }.distinctBy { it.className }

    /**
     * [className], else the first class a CU defines down its chain of first non-virtual bases, with
     * where that sits in [className]: `basic_ios` keeps its own vptr in front of `ios_base`, at +4.
     */
    private fun definedPart(className: String, depth: Int = 0): Pair<DataType, Int>? =
        structFor(className)?.let { it to 0 }
            ?: symbols.typeinfos[className]?.takeIf { depth < MAX_DEPTH }
                ?.let { reader.basesOf(it) }
                ?.filterNot { it.isVirtual }?.minByOrNull { it.offset }
                ?.let { base ->
                    definedPart(base.className, depth + 1)?.let { (dt, at) -> dt to at + base.offset.toInt() }
                }

    /** The class as its typeinfo and vtable demangle: its stated namespace chain, else its name. */
    private fun LocatedType.qualifiedName() = statedClassPath(registry.types)?.joinToString("::") ?: className

    private companion object {
        const val MAX_DEPTH = 16
    }
}
