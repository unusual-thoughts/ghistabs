package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghistabs.DEMANGLER_CATEGORY
import ghistabs.diagnose.DiagnosticSink
import ghistabs.index.LocatedType
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.componentsOverlapping
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.*
import ghistabs.materialize.cpp.baseSubobjects
import ghistabs.materialize.cpp.classBody
import ghistabs.materialize.cpp.layClasses
import ghistabs.materialize.cpp.layoutName
import ghistabs.materialize.cpp.placeBase
import ghistabs.parse.leafName
import ghistabs.parse.member
import ghistabs.parse.nameSegments

/**
 * [ClassApplier]'s pass over the virtual bases a class's stab can't show, laid where its vtable says they
 * are. A class deriving from `basic_ifstream<char>` where no CU defines that has no virtual base in its
 * stab for [layClasses] to lay; its typeinfo still says `basic_istream` has `basic_ios` as a virtual base
 * whose offset is 12 bytes behind the vtable's address point, and the class's `_ZTV` holds that offset
 * there. When no CU defines `basic_ios` either, the first base of it that one does is laid instead, where
 * `basic_ios`'s typeinfo puts it: `ios_base`, 4 bytes in, behind `basic_ios`'s own vptr.
 *
 * Itanium only: gcc 2.x fills its typeinfo at run time. A class whose stab shows a virtual base is
 * [layClasses]'s, and anything that would not fit, or would cover laid bytes, is reported and left. Runs
 * after [layClasses], so a class embedded as a base was embedded without what this lays.
 */
internal class RttiVirtualBases(val registry: DataTypeRegistry, val program: Program) : DiagnosticSink by registry {
    private val reader = Rtti.Reader(program)

    /** Two locations can fill one struct; the second would find the first one's bases laid. */
    private val done = mutableSetOf<Structure>()

    /** Lays the virtual bases [record]'s typeinfo gives [located], the class [struct] holds. */
    fun lay(located: LocatedType, struct: Structure, record: VtableRecord) {
        if (registry.types.hasVirtualBase(located.classBody) || !done.add(struct)) return
        val vbases = program.rttiOf(record)?.let(::virtualBases).orEmpty()
        val count = registry.baseSubobjects(located.classBody) + vbases.size
        for (vbase in vbases) layOne(struct, record, vbase, located.layoutName.member(vbase.className), count)
    }

    private fun layOne(struct: Structure, record: VtableRecord, vbase: Rtti.Reader.Base, at: String, count: Int) {
        val vbaseAt = program.vbaseOffset(record, vbase.offset)?.toInt()
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

            struct.componentsOverlapping(offset, dt.length).isNotEmpty() ->
                degradation("vbase-layout-failed", at, "${dt.name} at +$offset covers laid fields")

            else -> {
                val part = "; only its ${dt.name} at +$within is defined"
                    .takeUnless { within == 0 && dt.name == vbase.className.leafName }.orEmpty()
                val comment = "${vbase.access.name.lowercase()} virtual ${vbase.className} at " +
                    "+0x${vbaseAt.toString(16)}, by the vtable$part"
                registry.placeBase(
                    struct,
                    offset,
                    dt,
                    isVirtual = true,
                    comment,
                    ClassNaming.baseFieldName(true, dt.name, count),
                    at,
                )
            }
        }
    }

    /**
     * The struct for the class a typeinfo names. One whose members' mangled names tie it to our struct is
     * found by the `/Demangler` path its typeinfo demangles to as well ([DataTypeRegistry.byDemangledClass]).
     * One with no such member, a plain struct, is found by its stab tag, when only one struct has it.
     */
    private fun structFor(className: String) = className.nameSegments
        .let { registry.byDemangledClass[DEMANGLER_CATEGORY.extend(*it.toTypedArray()).path] as? Structure }
        .let { it ?: byTag(className.leafName) }
        ?.takeIf { registry.dtm.contains(it) && !it.isZeroLength }

    private fun byTag(tag: String) = registry.types.definitionsByTag[tag].orEmpty()
        .mapNotNull { registry.dataTypeFor(it.id) as? Structure }
        .distinct()
        .singleOrNull()

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

    private companion object {
        const val MAX_DEPTH = 16
    }
}
