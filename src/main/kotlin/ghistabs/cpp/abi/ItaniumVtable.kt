package ghistabs.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.*
import ghistabs.cpp.ClassNaming
import kotlin.math.abs

// The Itanium side of Vtable.kt: a record's header layout (ABI §2.5.2), finding a record's start
// and its group's secondaries in memory, and recognising a primary vtable with no symbol left on it.

/** Upper bound on vbase/vcall-offset words scanned before giving up on locating the rtti header. */
private const val MAX_VTABLE_PREFIX_WORDS = 64

/** Bound on a vbase offset, past which a word in front of `offset_to_top` is taken to be something else. */
private const val MAX_VBASE_OFFSET = 0x10000L

/** The header field holding an Itanium record's vbase/vcall-offset word [i], counted from the record start. */
fun vtableOffsetField(i: Int) = "vcall_vbase_offset_$i"

/**
 * The header of an Itanium vtable record with [prefixWords] vbase/vcall-offset words in front of
 * `offset_to_top` and the rtti pointer (ABI §2.5.2), one layout per prefix length the way
 * [Rtti.vmiClassTypeInfo] has one per base count. Unresolved, like [Rtti]'s: [vtableRecord] reads a
 * record through it without writing to the DTM, and [VtableRecord.lay] resolves it to lay one.
 */
fun vtableHeaderLayout(dtm: DataTypeManager, prefixWords: Int): StructureDataType {
    val word = Itanium.offsetToTopType(dtm.dataOrganization.pointerSize)
    val name = "VtableHeaderStructure${if (prefixWords > 0) prefixWords else ""}"
    return StructureDataType(ClassNaming.classDataTypesRoot, name, 0, dtm).apply {
        // One field a word, not an array: Ghidra shows no comment on a word inside an array inside a struct,
        // and each word gets its own saying which base it is for.
        repeat(prefixWords) { add(word, vtableOffsetField(it), null).showDecimal() }
        add(word, Itanium.OFFSET_TO_TOP, "to top of complete object").showDecimal()
        add(PointerDataType(dtm), Itanium.RTTI, null)
        isPackingEnabled = true
    }
}

/** What an Itanium primary vtable's address point starts with: `offset_to_top`, the rtti word, and slot 0. */
fun primaryHeader(dtm: DataTypeManager) = StructureDataType("PrimaryVtableHeader", 0).apply {
    add(Itanium.offsetToTopType(dtm.dataOrganization.pointerSize), Itanium.OFFSET_TO_TOP, null)
    add(PointerDataType(dtm), Itanium.RTTI, null)
    add(PointerDataType(dtm), "slot0", null)
    isPackingEnabled = true
}

/**
 * The Itanium primary vtable whose `offset_to_top` word is at [addr], read through [header] ([primaryHeader]),
 * or null if the words there don't have its shape. With no `_ZTV` symbol left to say where a class's vtable
 * is, [RttiSymbols] tries the word in front of each pointer to the class's typeinfo.
 *
 * A class's `_ZTV` is a group of vtables, called records here ([VtableRecord]; the ABI's "virtual table
 * group", §2.5.2). The primary one comes first, at the `_ZTV` symbol: it serves the class and its primary
 * base, an object's first vptr points into it, and its `offset_to_top` is 0. A secondary one follows for
 * each other base with virtual functions, its `offset_to_top` the negated offset of that base in the object.
 * A primary vtable's address point sits right after two header words:
 *
 *     [vbase/vcall offsets…]  offset_to_top  rtti       slot 0  slot 1 …
 *                             0              &typeinfo  &code
 *
 * so it matches when [addr] is in a data block, the word there is 0, and slot 0 points into code.
 *
 * - Slot 0 is required because a 0 then a typeinfo pointer isn't enough: an exception table's catch entry
 *   stores `{0, typeinfo}` too (`std::string`'s on crypto_mi, a class with no vtable at all). That costs a
 *   vtable with no slots of its own, a class whose only virtual parts are its bases.
 * - A base's construction vtable (`_ZTC`) has the same shape and holds the base's typeinfo, so one typeinfo
 *   can match more than one address; the caller decides between them.
 */
fun Program.primaryRecordAt(addr: Address, header: Structure) = addr.takeIf(::isData)?.let { dataAt(it, header) }
    ?.takeIf { it.valueOf<Scalar>(Itanium.OFFSET_TO_TOP)?.value == 0L }
    ?.takeIf { it.valueOf<Address>("slot0")?.let(::isCode) == true }

/**
 * Where the Itanium vtable record whose `offset_to_top` word is at [top] begins.
 *
 * A class with virtual bases puts a vbase or vcall offset per base in front of `offset_to_top`, so its
 * record starts before [top]. This walks back from [top] a word at a time while the word reads as such an
 * offset: signed, non-zero, smaller than [MAX_VBASE_OFFSET] either way, and not an address in code.
 * Anything else (the previous record's last slot, a typeinfo, padding) ends the walk. It returns the
 * last word that passed, or [top] when none did.
 *
 * An offset of 0 can't be told from padding, so the walk stops short of a record whose first offset is 0.
 * [RttiSymbols] moves such a start back once the class's typeinfo says where its vbases are.
 */
fun Program.recordStart(top: Address): Address {
    val word = IntegerDataType.getSignedDataType(defaultPointerSize, null)
    fun isVbaseOffset(v: Long) = v != 0L && abs(v) < MAX_VBASE_OFFSET &&
        runCatching { addressFactory.defaultAddressSpace.getAddress(v) }.getOrNull()?.let(::isCode) != true
    return generateSequence(top) { runCatching { it - defaultPointerSize }.getOrNull() }
        .drop(1)
        .takeWhile { at -> valueAt<Scalar>(at, word)?.signedValue?.let(::isVbaseOffset) == true }
        .lastOrNull() ?: top
}

/** The Itanium record at [start] whose rtti word sits at [rttiSlot], or the canonical 2-word one if null. */
private fun Program.recordAt(start: Address, rttiSlot: Address?, abi: CxxAbi): VtableRecord {
    val ptr = defaultPointerSize.toLong()
    val prefixWords = rttiSlot?.let { ((it - start) / ptr - 1).toInt() } ?: 0
    val header = vtableHeaderLayout(dataTypeManager, prefixWords)
    return VtableRecord(start, header, abi)
}

/**
 * Locate the fixed words of the Itanium record at [ztv], for [vtableRecord]. The address point is
 * *not* a fixed `ztv + 2*ptrSize`:
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
 */
internal fun Program.itaniumVtableRecord(ztv: Address, abi: CxxAbi): VtableRecord {
    val ptr = defaultPointerSize.toLong()
    fun holdsTypeinfo(slot: Address) =
        pointerAt(slot)?.let { pointee -> symbolTable.getSymbols(pointee).any { it.isTypeinfo } } == true

    val rttiSlot = generateSequence(ztv) { it.add(ptr) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { holdsTypeinfo(it) || pointerAt(it)?.let(::isCode) != true }
        .firstOrNull(::holdsTypeinfo)
    return recordAt(ztv, rttiSlot, abi)
}

/** A record of an Itanium `_ZTV` group: where its fixed words sit, and the function pointers it holds. */
data class SubVtable(val record: VtableRecord, val targets: List<Address>) {
    fun endOfSlots(ptrSize: Int): Address = record.slotsStart.add(targets.size.toLong() * ptrSize)
}

/**
 * The Itanium sub-vtable beginning at [start], or null if what is there does not belong to [rtti]'s group. One
 * with no slots is still a record: a base with no virtuals of its own keeps its vptr and header
 * (`Right` in `Diamond`, ahead of `Named`'s), and stopping at it would lose every record after it.
 */
private fun Program.subVtableAt(start: Address, rtti: Address): SubVtable? =
    generateSequence(start) { it.add(defaultPointerSize.toLong()) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { pointerAt(it) == rtti || pointerAt(it)?.let(::isCode) != true }
        // offset_to_top precedes rtti, so a match on the first word would put the top slot back
        // inside the primary's function array.
        .firstOrNull { it > start && pointerAt(it) == rtti }
        ?.let { recordAt(start, it, Itanium) }
        ?.let { record -> SubVtable(record, record.slots(this)) }

/**
 * The secondary sub-vtables following an Itanium primary record, whose slots end at [afterPrimary] — one per
 * virtual base, each its own `[vcall offsets…] offset_to_top rtti [thunks]` (ABI §2.5.2), none bearing
 * a symbol. Nothing delimits the group, so the walk is bounded by the one invariant that does: every
 * record in it describes the same complete object, hence carries the same [rtti] pointer. That alone
 * runs on into the next group when it shares the rtti: a construction vtable's names the base, and
 * CryptoPP lays `GeneratableCryptoMaterial`'s `-in-` groups for three classes back to back. So the walk
 * also stops at a record whose header holds the next group's own symbol.
 */
fun Program.secondaryVtables(afterPrimary: Address, rtti: Address): List<SubVtable> =
    generateSequence(subVtableAt(afterPrimary, rtti)) {
        subVtableAt(it.endOfSlots(defaultPointerSize), rtti)
    }.takeWhile { sub -> !sub.record.opensGroup(this) }.toList()
