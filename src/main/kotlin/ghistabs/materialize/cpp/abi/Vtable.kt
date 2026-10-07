package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghistabs.Demangler
import ghistabs.forceCreateData
import ghistabs.materialize.DtmRegistry
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.readAt
import ghistabs.readPointer
import ghistabs.valueOf

/** Upper bound on vbase/vcall-offset words scanned before giving up on locating the rtti header. */
private const val MAX_VTABLE_PREFIX_WORDS = 64

/**
 * The pointer at [a], or null if it is unmapped or does not point into executable memory. The one test
 * that separates a vtable's function pointers from its header words — both scans below turn on it, and
 * neither can use symbol presence, which auto-analysis sprays `PTR_` labels across. An rtti word can
 * pass it too: an old i386 ELF links `.rodata`, typeinfo and all, into the R-X text segment, so the
 * scans exempt the rtti word before asking.
 *
 * Read as it stands, never through [ghistabs.harvest.AddressResolver.buildAddress]: that fixup is for
 * stab values, which nothing relocated, while the loader has already relocated what memory holds — a
 * PIE loaded at 0x10000 would otherwise have every vtable pointer moved another 0x10000 off its target.
 */
private fun Program.codeTargetAt(a: Address) = readPointer(a)?.takeIf { memory.getBlock(it)?.isExecute == true }

/** The header field holding an Itanium record's vbase/vcall-offset words, when it has any. */
const val VTABLE_OFFSETS = "vcall_vbase_offsets"

/**
 * The header of an Itanium vtable record with [prefixWords] vbase/vcall-offset words in front of
 * `offset_to_top` and the rtti pointer (ABI §2.5.2), one layout per prefix length the way
 * [Rtti.vmiClassTypeInfo] has one per base count. Unresolved, like [Rtti]'s: [vtableRecord] reads a
 * record through it without writing to the DTM, and [layVtable] resolves it to lay one.
 */
fun vtableHeaderLayout(dtm: DataTypeManager, prefixWords: Int): StructureDataType {
    val word = Itanium.offsetToTopType(dtm.dataOrganization.pointerSize)
    val name = "VtableHeaderStructure${if (prefixWords > 0) prefixWords else ""}"
    return StructureDataType(ClassNaming.classDataTypesRoot, name, 0, dtm).apply {
        if (prefixWords > 0) {
            add(ArrayDataType(word, prefixWords, word.length, dtm), VTABLE_OFFSETS, null).showDecimal()
        }
        add(word, Itanium.OFFSET_TO_TOP, "to top of complete object").showDecimal()
        add(PointerDataType(dtm), Itanium.RTTI, null)
        isPackingEnabled = true
    }
}

/**
 * A vtable record, located: where it starts, the [header] laid there, and the [addressPoint] its function
 * array starts at. An Itanium record's header is a [vtableHeaderLayout], read back through it ([readHeader]).
 * A gcc 2.x record has none: its reserved entry belongs to the vftable struct, and its `{vfptr}` holds
 * the record start rather than the address point. Built by [vtableRecord].
 */
data class VtableRecord(val address: Address, val header: StructureDataType?, val addressPoint: Address) {
    /** The vbase/vcall-offset words in front of `offset_to_top`. */
    val prefixWords get() = (header?.field(VTABLE_OFFSETS)?.dataType as? ArrayDataType)?.numElements ?: 0

    /** What a `{vfptr}` pointing into this record holds, where the `vftable` label goes. */
    val vptrTarget get() = if (header == null) address else addressPoint

    /** Where [header]'s field [name] sits in memory. */
    fun fieldAddress(name: String): Address? = header?.field(name)?.let { address.add(it.offset.toLong()) }

    private fun StructureDataType.field(name: String) = components.firstOrNull { it.fieldName == name }
}

/** [record]'s header as memory holds it, read through its layout; null for a gcc 2.x record. */
fun Program.readHeader(record: VtableRecord): Data? = record.header?.let { readAt(record.address, it) }

/** The typeinfo [record]'s rtti word points at. */
fun Program.rttiOf(record: VtableRecord): Address? = readHeader(record)?.valueOf<Address>(Itanium.RTTI)

/** The Itanium record at [start] whose rtti word sits at [rttiSlot], or the canonical 2-word one if null. */
private fun Program.recordAt(start: Address, rttiSlot: Address?): VtableRecord {
    val ptr = defaultPointerSize.toLong()
    val prefixWords = rttiSlot?.let { (it.subtract(start) / ptr - 1).toInt() } ?: 0
    val header = vtableHeaderLayout(dataTypeManager, prefixWords)
    return VtableRecord(start, header, start.add(header.length.toLong()))
}

/**
 * What prefix word [i] of [total] is, given the class's [virtualBases]. The ABI orders the words
 * before `offset_to_top` as vcall offsets then vbase offsets (§2.5.2), one vbase offset per virtual
 * base — so knowing how many virtual bases the stab declares splits the run from the right-hand end,
 * and names each vbase word. A vbase offset of 0 is normal, not a gap: an empty abstract base sits at
 * offset 0 (CryptoPP's interface lattice gives eleven vtables twelve zeroed vbase offsets).
 *
 * Falls back to the undifferentiated label when the stab declares no virtual base — either the class
 * genuinely has none and this is a swept class we know nothing about, or the count disagrees, which
 * [ghistabs.importer.ClassApplier] reports separately.
 */
private fun prefixKind(i: Int, total: Int, virtualBases: List<String>): String {
    val vcalls = total - virtualBases.size
    if (virtualBases.isEmpty() || vcalls < 0) return "vbase/vcall offset"
    // Naming the word only when there is one virtual base to name. The ABI fixes the order of the
    // vbase offsets, but nothing here has verified it against a class with several, and a confidently
    // wrong base name in a comment is worse than none.
    return when {
        i < vcalls -> "vcall offset"
        virtualBases.size == 1 -> "vbase offset: ${virtualBases.single()}"
        else -> "vbase offset"
    }
}

/**
 * Locate the fixed words of the record at [ztv]. The address point is *not* a fixed `ztv + 2*ptrSize`:
 * a class with a virtual base anywhere in its hierarchy (anything derived from an iostream —
 * `basic_istream` virtually inherits `basic_ios`) has vbase/vcall-offset words before offset_to_top,
 * so `_ZTV<class>` points that many words early. Find the rtti header instead — the one word holding
 * the address of a `_ZTI…` symbol — and read the other two off it. Falls back to the canonical
 * 2-word header when no such word is in reach (templates, stripped rtti).
 *
 * The search stops at the first word that points into code, which is this record's own function
 * array: reaching it means the record has no rtti header, and without that stop the scan would run
 * on into the *next* record and adopt its rtti — laying offset_to_top, the address point and a run
 * of "vbase offset" comments inside the wrong object. `MAX_VTABLE_PREFIX_WORDS` alone never bounded
 * that, it only capped how far the damage spread.
 *
 * A gcc 2.x record has no typeinfo pointer to search for ([CxxAbi.hasRttiHeader]) and no
 * vbase/vcall prefix either, so it gets no header layout, and its address point is past the reserved
 * entry.
 */
fun Program.vtableRecord(ztv: Address, abi: CxxAbi = Itanium): VtableRecord {
    if (!abi.hasRttiHeader) return VtableRecord(ztv, null, ztv.add(abi.headerBytes(defaultPointerSize)))
    val ptr = defaultPointerSize.toLong()
    fun holdsTypeinfo(slot: Address) =
        readPointer(slot)?.let { pointee -> symbolTable.getSymbols(pointee).any { it.isTypeinfo } } == true
    val rttiSlot = generateSequence(ztv) { it.add(ptr) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { holdsTypeinfo(it) || codeTargetAt(it) == null }
        .firstOrNull(::holdsTypeinfo)
    return recordAt(ztv, rttiSlot)
}

/** A record of a `_ZTV` group: where its fixed words sit, and the function pointers it holds. */
data class SubVtable(val record: VtableRecord, val targets: List<Address>) {
    fun endOfSlots(ptrSize: Int): Address = record.addressPoint.add(targets.size.toLong() * ptrSize)
}

/**
 * The secondary sub-vtables following the primary record, whose slots end at [afterPrimary] — one per
 * virtual base, each its own `[vcall offsets…] offset_to_top rtti [thunks]` (ABI §2.5.2), none bearing
 * a symbol. Nothing delimits the group, so the walk is bounded by the one invariant that does: every
 * record in it describes the same complete object, hence carries the same [rtti] pointer.
 */
fun Program.secondaryVtables(afterPrimary: Address, rtti: Address): List<SubVtable> =
    generateSequence(subVtableAt(afterPrimary, rtti)) {
        subVtableAt(it.endOfSlots(defaultPointerSize), rtti)
    }.toList()

/**
 * The sub-vtable beginning at [start], or null if what is there does not belong to [rtti]'s group. One
 * with no slots is still a record: a base with no virtuals of its own keeps its vptr and header
 * (`Right` in `Diamond`, ahead of `Named`'s), and stopping at it would lose every record after it.
 */
private fun Program.subVtableAt(start: Address, rtti: Address): SubVtable? {
    val ptr = defaultPointerSize.toLong()
    val rttiSlot = generateSequence(start) { it.add(ptr) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { readPointer(it) == rtti || codeTargetAt(it) == null }
        // offset_to_top precedes rtti, so a match on the first word would put the top slot back
        // inside the primary's function array.
        .firstOrNull { it > start && readPointer(it) == rtti }
        ?: return null
    val record = recordAt(start, rttiSlot)
    return SubVtable(record, vtableSlotTargets(record.addressPoint))
}

/**
 * Addresses the function-pointer array at [addressPoint] holds, in slot order. Nothing records its
 * length, so it ends where the entries stop pointing into executable memory — at the next record's
 * `offset_to_top` (0) or rtti pointer (into .data). Walks by [abi]'s entry stride and reads `pfn` at
 * its offset within the entry, which is what separates a gcc 2.x table without thunks from one with.
 */
fun Program.vtableSlotTargets(addressPoint: Address, abi: CxxAbi = Itanium): List<Address> =
    generateSequence(addressPoint) { it.add(abi.stride(defaultPointerSize)) }
        .map { codeTargetAt(it.add(abi.pfnOffset(defaultPointerSize))) }
        .takeWhile { it != null }
        .filterNotNull()
        .toList()

/**
 * The `rtti:` header comment, reporting the typeinfo symbol that is actually there. [Itanium.zti]
 * builds a closed-form name, and for anything the shorthand or a template spells differently that
 * name does not exist: `std::istream`'s record is `_ZTISi`, not `_ZTIN3std7istreamE`. Prefers the
 * linkage name over Ghidra's own demangled label, which is also a symbol at that address and would
 * render as "rtti: typeinfo typeinfo".
 */
private fun Program.rttiComment(record: VtableRecord, className: String): String {
    val name = rttiOf(record)
        ?.let { symbolTable.getSymbols(it).map { s -> s.name } }
        ?.let { names -> names.firstOrNull(Itanium::looksLikeZti) ?: names.firstOrNull() }
        ?: Itanium.zti(className)
    return "${Itanium.RTTI}: $name typeinfo"
}

/**
 * Lay [record], and return the address its `{vfptr}` holds — where the [vftable] struct and the
 * `vftable` label go, so a constructor's `this->vfptr = &<Class>::vftable` resolves to a symbol and a
 * virtual call resolves to one of its fields.
 *
 * Itanium points at the address point, and the record's header is laid in front of it as its
 * [vtableHeaderLayout], resolved through [registry]; the rtti pointee stays an untyped `void*` until
 * backlog §24 wires it. Each header word also gets an EOL comment saying what it holds for this class,
 * which the shared layout cannot. gcc 2.x points at the record start, so its reserved header is *inside*
 * the struct — laid as fields by the caller rather than here, because a header struct there would
 * collide with the vftable covering the same bytes.
 */
fun Program.layVtable(
    registry: DtmRegistry,
    record: VtableRecord,
    vftable: Structure,
    className: String,
    ns: Namespace,
    virtualBases: List<String> = emptyList(),
    internal: Boolean = false,
    source: SourceType = SourceType.IMPORTED,
): Address {
    // gcc 2.x labels the record start, because that is what a `{vfptr}` holds. The struct is *not*
    // stamped over the bytes: gcc declares the record itself (`__vtbl_ptr_type __vt_9TiXmlNode[20]`),
    // which is authoritative on length in a way nothing here is, and a virtual call resolves off the
    // vfptr's pointee type rather than off whatever data is applied at the target.
    val header = record.header ?: run {
        listing.setComment(record.address, CommentType.EOL, "gcc 2.x vtable: reserved entry, then the slots")
        labelVtable(record.address, ClassNaming.vftableLabel(internal), ns, source)
        return record.address
    }

    labelVtable(record.address, ClassNaming.vtableLabel(internal), ns, source)
    forceCreateData(record.address, registry.resolveLayout(header))
    val ptr = defaultPointerSize.toLong()
    for (i in 0 until record.prefixWords) {
        val kind = prefixKind(i, record.prefixWords, virtualBases)
        listing.setComment(record.address.add(i * ptr), CommentType.EOL, kind)
    }
    record.fieldAddress(Itanium.OFFSET_TO_TOP)?.let {
        listing.setComment(it, CommentType.EOL, "${Itanium.OFFSET_TO_TOP} (to top of complete object)")
    }
    record.fieldAddress(Itanium.RTTI)?.let { listing.setComment(it, CommentType.EOL, rttiComment(record, className)) }
    forceCreateData(record.addressPoint, vftable)
    labelVtable(record.addressPoint, ClassNaming.vftableLabel(internal), ns, source)
    return record.addressPoint
}

/**
 * `createLabel` hands back a label already there as it stands, so a class laying a table an earlier
 * sweep labelled has to raise the label's source itself: that source is what [isVtableClaimed] reads.
 */
private fun Program.labelVtable(at: Address, label: String, ns: Namespace, source: SourceType) {
    val sym = symbolTable.createLabel(at, label, ns, source)
    if (source == SourceType.IMPORTED && sym.source != source) sym.source = source
}

/**
 * Whether a class that describes [record] already laid it: [layVtable] with
 * [SourceType.IMPORTED] left a `vftable` or `internal_vftable` label where its `{vfptr}` points. This
 * is how a sweep tells what is left without the class pass's own bookkeeping. A swept table is
 * labelled [SourceType.ANALYSIS], so a later sweep lays it again rather than skipping it.
 */
fun Program.isVtableClaimed(record: VtableRecord): Boolean = symbolTable.getSymbols(record.vptrTarget)
    .any { it.source == SourceType.IMPORTED && it.name in claimLabels }

private val claimLabels = listOf(true, false).map { ClassNaming.vftableLabel(it) }

/** Where a class's vtable record sits, and which ABI lays it out past the header. */
data class ResolvedVtable(val className: String, val address: Address, val abi: CxxAbi) {
    companion object {
        /** For a caller that already knows the class and is only checking a spelling of it. */
        fun of(className: String, symName: String, addr: Address) =
            CxxAbi.ofVtableSymbol(symName)?.let { ResolvedVtable(className, addr, it) }

        /**
         * For a caller holding only the symbol, which has to demangle to learn the class. gcc 2.x
         * needs the primary screen on top of [CxxAbi.ofVtableSymbol]: a second cplus-marker separates a base,
         * naming that base's secondary table rather than the class's own.
         */
        fun fromSymbol(sym: Symbol) = CxxAbi.ofVtableSymbol(sym.name)
            ?.takeIf { it.isPrimaryVtable(sym.name) }
            ?.let { abi ->
                Demangler.of(sym.name)
                    ?.let(abi::demangledVtableClass)
                    ?.let { ResolvedVtable(it, sym.address, abi) }
            }
    }
}
