package ghistabs.materialize.cpp

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.diagnose.DiagnosticSink
import ghistabs.index.LocatedType
import ghistabs.index.ScopeLocator
import ghistabs.index.TypeLocation
import ghistabs.index.scopeCategory
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.cpp.abi.*
import ghistabs.parse.leafName
import ghistabs.parse.member
import ghistabs.parse.nameSegments
import ghistabs.readAs

/**
 * The virtual bases a class's stab can't show, laid where its vtable says they are. A class deriving
 * from `basic_ifstream<char>` where no CU defines that has no virtual base in its stab for [layClasses] to
 * lay; its typeinfo still says `basic_istream` has `basic_ios` as a virtual base whose offset is 12 bytes
 * behind the vtable's address point, and the class's `_ZTV` holds that offset there. When no CU defines
 * `basic_ios` either, the first base of it that one does is laid instead, where `basic_ios`'s typeinfo
 * puts it: `ios_base`, 4 bytes in, behind `basic_ios`'s own vptr.
 *
 * Itanium only: gcc 2.x fills its typeinfo at run time. A class whose stab shows a virtual base is
 * [layClasses]'s, and anything that would not fit, or would cover laid bytes, is reported and left. Runs
 * after [layClasses], so a class embedded as a base was embedded without what this lays.
 */
internal fun DataTypeRegistry.layVirtualBasesFromVtables(program: Program) = VtableVirtualBases(this, program).layAll()

/** [vtables] is each class's Itanium `_ZTV`, by the qualified name it demangles to. */
private class VtableVirtualBases(val registry: DataTypeRegistry, val program: Program) : DiagnosticSink by registry {
    private val reader = Rtti.Reader(program)
    private val word = Itanium.offsetToTopType(program.defaultPointerSize)

    val vtables = buildMap {
        for (sym in program.symbolTable.getSymbolIterator(true)) {
            ResolvedVtable.fromSymbol(sym)?.takeIf { it.abi == Itanium }?.let { putIfAbsent(it.className, it.address) }
        }
    }

    fun layAll() {
        if (vtables.isEmpty()) {
            return
        }
        val done = mutableSetOf<Structure>()
        for (located in registry.classesBasesFirst()) {
            if (registry.types.hasVirtualBase(located.classBody)) continue
            val struct = registry.dataTypeFor(located.type.id) as? Structure ?: continue
            if (!done.add(struct)) continue
            val record = vtables[located.qualifiedName()]
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
        // A nearly-empty virtual base can be the primary base, sharing the class's vptr at 0 (CryptoPP's
        // CryptoMaterial under CryptoParameters): there is nothing of its own to lay.
        if (vbaseAt == 0) return debug("vbase-primary-from-vtable")
        if (vbaseAt == null || vbaseAt < 0 || vbaseAt >= struct.length) {
            return degradation("vbase-offset-unreadable", at, "vtable word at ${vbase.offset} reads $vbaseAt")
        }
        val (dt, within) = definedPart(vbase)
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
                val part = "; only its ${dt.name} at +$within is defined"
                    .takeUnless { within == 0 && dt.name == vbase.className.leafName }.orEmpty()
                val comment = "${vbase.access.name.lowercase()} virtual ${vbase.className} at " +
                    "+0x${vbaseAt.toString(16)}, by the vtable$part"
                struct.replaceAtOffset(offset, dt, dt.length, ClassNaming.baseFieldName(true, dt.name, count), comment)
            }.onSuccess { debug("vbase-applied-from-vtable") }
                .onFailure { degradation("vbase-layout-failed", at, it.message) }
        }
    }

    /**
     * The struct filed where [className] says: a class gcc stated a scope for is located at its demangled
     * path ([ScopeLocator]), the one its typeinfo's symbol demangles to as well. One it stated none for,
     * having no out-of-line member, is filed by where it was declared instead, so only its name finds
     * it, and only when no other struct has that name.
     */
    private fun structFor(className: String) = className.nameSegments
        .let { registry.byLocation[TypeLocation(scopeCategory(it.dropLast(1)), it.last())] }
        ?.let { registry.dataTypeFor(it.type.id) as? Structure }
        .let { it ?: byLeaf[className.leafName] }
        ?.takeIf { registry.dtm.contains(it) && !it.isZeroLength }

    private val byLeaf: Map<String, Structure> by lazy {
        registry.byLocation.values
            .groupBy({ it.className.leafName }, { registry.dataTypeFor(it.type.id) as? Structure })
            .mapNotNull { (leaf, all) -> all.filterNotNull().distinct().singleOrNull()?.let { leaf to it } }
            .toMap()
    }

    /** [zti]'s virtual bases, its own and those of its primary chain, each with its vtable offset. */
    private fun virtualBases(zti: Address, depth: Int = 0): List<Rtti.Reader.Base> =
        reader.basesOf(zti).orEmpty().takeIf { depth < MAX_DEPTH }.orEmpty().flatMap { base ->
            when {
                base.isVirtual -> listOf(base)
                base.offset == 0L -> virtualBases(base.typeinfo, depth + 1)
                else -> emptyList()
            }
        }.distinctBy { it.className }

    /**
     * [base], else the first class a CU defines down its chain of first non-virtual bases, with where
     * that sits in [base]: `basic_ios` keeps its own vptr in front of `ios_base`, at +4.
     */
    private fun definedPart(base: Rtti.Reader.Base, depth: Int = 0): Pair<DataType, Int>? =
        structFor(base.className)?.let { it to 0 } ?: base.typeinfo.takeIf { depth < MAX_DEPTH }?.let(reader::basesOf)
            ?.filterNot { it.isVirtual }?.minByOrNull { it.offset }
            ?.let { next -> definedPart(next, depth + 1)?.let { (dt, at) -> dt to at + next.offset.toInt() } }

    /** The class as its typeinfo and vtable demangle: its stated namespace chain, else its name. */
    private fun LocatedType.qualifiedName() = statedClassPath(registry.types)?.joinToString("::") ?: className

    private companion object {
        const val MAX_DEPTH = 16
    }
}
