package ghistabs.materialize.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.forceCreateData
import ghistabs.harvest.AddressResolver

/** Upper bound on vbase/vcall-offset words scanned before giving up on locating the rtti header. */
private const val MAX_VTABLE_PREFIX_WORDS = 64

/** Pointer-sized word at [a] from initialized memory (endianness-aware), or null if unmapped. */
internal fun Program.readWord(a: Address): Long? = runCatching {
    if (defaultPointerSize == 8) memory.getLong(a) else memory.getInt(a).toLong() and 0xFFFFFFFFL
}.getOrNull()

/** The word at [a] read as an address, or null if it is unmapped or does not point into executable
 *  memory. The one test that separates a vtable's function pointers from its header words — both
 *  scans below turn on it, and neither can use symbol presence, which auto-analysis sprays `PTR_`
 *  labels across. */
private fun Program.codeTargetAt(a: Address, resolver: AddressResolver): Address? =
    readWord(a)?.let(resolver::buildAddress)?.takeIf { memory.getBlock(it)?.isExecute == true }

/**
 * How a vtable record is laid out past its header, which the symbol's spelling decides.
 *
 * The gcc 2.x geometry is gcc 2.95.3's: `cp/decl.c` makes an entry a bare function pointer under
 * `-fvtable-thunks` and the record `{short delta; short index; void *pfn;}` without, while
 * `cp/class.c:skip_rtti_stuff` always reserves one entry for the offset/tdesc entry and a second,
 * for the tdesc pointer, only with thunks. Two pointers or one 8-byte record: the header is 8 bytes
 * on 32-bit either way, so [Itanium.vtablePrefixBytes] locates every address point here and only
 * the stride past it differs.
 */
enum class VtableAbi {
    /** `_ZTV`: pointer-sized entries after the offset_to_top + rtti header. */
    ITANIUM,

    /** `__vt_`: `-fvtable-thunks`, the `this` adjustment moved into a thunk, so an entry is the pfn. */
    GCC2_THUNKS,

    /** `_vt.`/`_vt$`: `{delta, index, pfn}` entries, twice as wide, with pfn in the second word. */
    GCC2_PLAIN,
    ;

    /** Bytes between consecutive entries. */
    fun stride(ptrSize: Int) = if (this == GCC2_PLAIN) 2L * ptrSize else ptrSize.toLong()

    /**
     * Where `pfn` sits inside an entry. `delta` and `index` are a `short` each, so together they
     * make exactly one 32-bit word — the only width gcc 2.x ever targeted. (`-fhuge-objects` widens
     * both to `long` and would make this `2 * ptrSize`; no corpus binary uses it.)
     */
    fun pfnOffset(ptrSize: Int) = if (this == GCC2_PLAIN) ptrSize.toLong() else 0L

    /** gcc 2.x emits no typeinfo pointer, so there is no rtti word to find the address point by. */
    val hasRttiHeader get() = this == ITANIUM

    /**
     * Whether a `{vfptr}` holds the record *start* rather than the address point, which decides where
     * the `_vftable` struct has to begin for a virtual call to resolve against its fields.
     *
     * Itanium points at the address point, past the header. gcc 2.x points at the record start and
     * the call site skips the header itself — `cv_mscom_elf_i386_gcc281` stores `_vt.9CMapBytes`
     * verbatim into the object (`movl $0x807639c,(%ebx)`), and `tinyxml_aout_gcc295.o` dispatches
     * through `add eax,0x8` after loading the vptr. So a gcc 2.x struct based at the address point
     * describes memory 8 bytes along from what the object actually points at, and the decompiler
     * can only fall back to `(**(code **)(*(int *)(this + 0xc) + 0x44))()`.
     */
    val vptrAtRecordStart get() = this != ITANIUM

    /** Bytes of reserved header before the first virtual's entry (`cp/class.c:skip_rtti_stuff`). */
    fun headerBytes(ptrSize: Int) = Itanium.vtablePrefixBytes(ptrSize)

    /** Byte offset of slot [index]'s `pfn` from wherever the struct begins. */
    fun slotOffset(index: Int, ptrSize: Int) =
        (if (vptrAtRecordStart) headerBytes(ptrSize) else 0L) + index * stride(ptrSize) + pfnOffset(ptrSize)

    companion object {
        fun of(symbolName: String) = when {
            Gcc2.looksLikeThunkVtable(symbolName) -> GCC2_THUNKS
            Gcc2.looksLikeVtable(symbolName) -> GCC2_PLAIN
            else -> ITANIUM
        }
    }
}

/**
 * An Itanium vtable record, decomposed: the [prefix] of vbase/vcall-offset words, then the two fixed
 * header words, then the address point the function array starts at. Built by [vtableShape].
 */
data class VtableShape(
    val prefix: List<Address>,
    val topSlot: Address,
    val rttiHeader: Address,
    val addressPoint: Address,
)

/** The record at [start] whose rtti word sits at [rttiSlot], or the canonical 2-word shape if null. */
private fun Program.shapeOf(start: Address, rttiSlot: Address?): VtableShape {
    val ptr = defaultPointerSize.toLong()
    val topSlot = rttiSlot?.subtract(ptr) ?: start
    return VtableShape(
        prefix = generateSequence(start) { it.add(ptr) }.takeWhile { it < topSlot }.toList(),
        topSlot = topSlot,
        rttiHeader = rttiSlot ?: start.add(ptr),
        addressPoint = rttiSlot?.add(ptr) ?: start.add(Itanium.vtablePrefixBytes(defaultPointerSize)),
    )
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
 * [ghistabs.materialize.ClassBuilder] reports separately.
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
 * 2-word shape when no such word is in reach (templates, stripped rtti).
 *
 * The search stops at the first word that points into code, which is this record's own function
 * array: reaching it means the record has no rtti header, and without that stop the scan would run
 * on into the *next* record and adopt its rtti — laying offset_to_top, the address point and a run
 * of "vbase offset" comments inside the wrong object. `MAX_VTABLE_PREFIX_WORDS` alone never bounded
 * that, it only capped how far the damage spread.
 *
 * A gcc 2.x record has no typeinfo pointer to search for ([VtableAbi.hasRttiHeader]) and no
 * vbase/vcall prefix either, so its address point is the canonical shape outright.
 */
fun Program.vtableShape(ztv: Address, resolver: AddressResolver, abi: VtableAbi = VtableAbi.ITANIUM): VtableShape {
    if (!abi.hasRttiHeader) return shapeOf(ztv, null)
    val ptr = defaultPointerSize.toLong()
    val rttiSlot = generateSequence(ztv) { it.add(ptr) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { codeTargetAt(it, resolver) == null }
        .firstOrNull { slot ->
            readWord(slot)?.let { value ->
                symbolTable.getSymbols(resolver.buildAddress(value)).any {
                    Itanium.looksLikeZti(it.name) || it.name == Itanium.DEMANGLED_TYPEINFO
                }
            } == true
        }
    return shapeOf(ztv, rttiSlot)
}

/** A record of a `_ZTV` group: where its fixed words sit, and the function pointers it holds. */
data class SubVtable(val shape: VtableShape, val targets: List<Address>) {
    fun endOfSlots(ptrSize: Int): Address = shape.addressPoint.add(targets.size.toLong() * ptrSize)
}

/**
 * The secondary sub-vtables following the primary record, whose slots end at [afterPrimary] — one per
 * virtual base, each its own `[vcall offsets…] offset_to_top rtti [thunks]` (ABI §2.5.2), none bearing
 * a symbol. Nothing delimits the group, so the walk is bounded by the one invariant that does: every
 * record in it describes the same complete object, hence carries the same [rtti] pointer.
 */
fun Program.secondaryVtables(afterPrimary: Address, rtti: Long, resolver: AddressResolver): List<SubVtable> =
    generateSequence(subVtableAt(afterPrimary, rtti, resolver)) {
        subVtableAt(it.endOfSlots(defaultPointerSize), rtti, resolver)
    }.toList()

/** The sub-vtable beginning at [start], or null if what is there does not belong to [rtti]'s group. */
private fun Program.subVtableAt(start: Address, rtti: Long, resolver: AddressResolver): SubVtable? {
    val ptr = defaultPointerSize.toLong()
    val rttiSlot = generateSequence(start) { it.add(ptr) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { codeTargetAt(it, resolver) == null }
        // offset_to_top precedes rtti, so a match on the first word would put the top slot back
        // inside the primary's function array.
        .firstOrNull { it > start && readWord(it) == rtti }
        ?: return null
    val shape = shapeOf(start, rttiSlot)
    return vtableSlotTargets(shape.addressPoint, resolver)
        .takeIf { it.isNotEmpty() }
        ?.let { SubVtable(shape, it) }
}

/**
 * Addresses the function-pointer array at [addressPoint] holds, in slot order. Nothing records its
 * length, so it ends where the entries stop pointing into executable memory — at the next record's
 * `offset_to_top` (0) or rtti pointer (into .data). Walks by [abi]'s entry stride and reads `pfn` at
 * its offset within the entry, which is what separates a gcc 2.x table without thunks from one with.
 */
fun Program.vtableSlotTargets(
    addressPoint: Address,
    resolver: AddressResolver,
    abi: VtableAbi = VtableAbi.ITANIUM,
): List<Address> = generateSequence(addressPoint) { it.add(abi.stride(defaultPointerSize)) }
    .map { codeTargetAt(it.add(abi.pfnOffset(defaultPointerSize)), resolver) }
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
private fun Program.rttiComment(rttiHeader: Address, className: String, resolver: AddressResolver): String {
    val name = readWord(rttiHeader)
        ?.let { symbolTable.getSymbols(resolver.buildAddress(it)).map { s -> s.name } }
        ?.let { names -> names.firstOrNull(Itanium::looksLikeZti) ?: names.firstOrNull() }
        ?: Itanium.zti(className)
    return "${Itanium.RTTI}: $name typeinfo"
}

/**
 * Lay the vtable record whose geometry is [shape], and return the address its `{vfptr}` holds — where
 * the [vftable] struct and the [label] symbol go, so a constructor's `this->vfptr = &<Class>::vftable`
 * resolves to a symbol and a virtual call resolves to one of its fields.
 *
 * Which address that is comes from [VtableAbi.vptrAtRecordStart]. Itanium points at the address point
 * and the `[vbase/vcall offsets…] offset_to_top rtti` header is laid in front of it as loose words;
 * the rtti pointee stays an untyped `void*` until backlog §24 wires it. gcc 2.x points at the record
 * start, so its reserved header is *inside* the struct — laid as fields by the caller rather than as
 * words here, because a loose Data item there would collide with the struct covering the same bytes.
 */
fun Program.layVtable(
    shape: VtableShape,
    vftable: Structure,
    className: String,
    ns: Namespace,
    resolver: AddressResolver,
    virtualBases: List<String> = emptyList(),
    label: String = Itanium.VFTABLE,
    abi: VtableAbi = VtableAbi.ITANIUM,
): Address {
    val (prefix, topSlot, rttiHeader, addressPoint) = shape

    // gcc 2.x labels the record start, because that is what a `{vfptr}` holds. The struct is *not*
    // stamped over the bytes: gcc declares the record itself (`__vtbl_ptr_type __vt_9TiXmlNode[20]`),
    // which is authoritative on length in a way nothing here is, and a virtual call resolves off the
    // vfptr's pointee type rather than off whatever data is applied at the target.
    if (abi.vptrAtRecordStart) {
        listing.setComment(topSlot, CommentType.EOL, "gcc 2.x vtable: reserved entry, then the slots")
        symbolTable.createLabel(topSlot, label, ns, SourceType.IMPORTED)
        return topSlot
    }

    prefix.forEachIndexed { i, slot ->
        forceCreateData(slot, Itanium.offsetToTopType(defaultPointerSize))
        listing.setComment(slot, CommentType.EOL, prefixKind(i, prefix.size, virtualBases))
    }
    forceCreateData(topSlot, Itanium.offsetToTopType(defaultPointerSize))
    listing.setComment(topSlot, CommentType.EOL, "${Itanium.OFFSET_TO_TOP} (to top of complete object)")
    forceCreateData(rttiHeader, PointerDataType(dataTypeManager))
    listing.setComment(rttiHeader, CommentType.EOL, rttiComment(rttiHeader, className, resolver))
    forceCreateData(addressPoint, vftable)
    symbolTable.createLabel(addressPoint, label, ns, SourceType.IMPORTED)
    return addressPoint
}
