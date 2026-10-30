package ghistabs.cpp.abi.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.*
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.abi.CxxAbi
import ghistabs.cpp.abi.VtableRecord
import kotlin.math.abs

// Itanium vtable records in memory (ABI §2.5.2): their headers, their starts, a group's secondaries, and
// a primary with no symbol left on it.

/** How many words to look through for an rtti word before giving up. */
private const val MAX_VTABLE_PREFIX_WORDS = 64

/** The largest vbase offset believed; a larger word in front of `offset_to_top` is something else. */
private const val MAX_VBASE_OFFSET = 0x10000L

/** The name of a header's vbase/vcall offset word [i], counted from the record start. */
fun vtableOffsetField(i: Int) = "vcall_vbase_offset_$i"

/**
 * A vtable header: [prefixWords] vbase/vcall offsets, `offset_to_top` and the rtti pointer. Unresolved, so
 * reading a record leaves the DTM alone; [ghistabs.cpp.abi.VtableRecord.lay] resolves it.
 */
fun DataTypeManager.vtableHeaderLayout(prefixWords: Int): StructureDataType {
    val word = Itanium.offsetToTopType(dataOrganization.pointerSize)
    val name = "VtableHeaderStructure${if (prefixWords > 0) prefixWords else ""}"
    return StructureDataType(ClassNaming.classDataTypesRoot, name, 0, this).apply {
        // A field per word rather than an array, as Ghidra shows no comment on an array element.
        repeat(prefixWords) { add(word, vtableOffsetField(it), null).showDecimal() }
        add(word, Itanium.OFFSET_TO_TOP, "to top of complete object").showDecimal()
        add(PointerDataType(this), Itanium.RTTI, null)
        isPackingEnabled = true
    }
}

/** What an Itanium primary vtable's address point starts with: `offset_to_top`, the rtti word, and slot 0. */
fun DataTypeManager.primaryHeader() = StructureDataType("PrimaryVtableHeader", 0).apply {
    add(Itanium.offsetToTopType(dataOrganization.pointerSize), Itanium.OFFSET_TO_TOP, null)
    add(PointerDataType(this), Itanium.RTTI, null)
    add(PointerDataType(this), "slot0", null)
    isPackingEnabled = true
}

/**
 * The primary vtable whose `offset_to_top` is at [addr], read through [header] ([primaryHeader]), or null
 * where the words don't fit: data, then 0, the typeinfo pointer, and a slot 0 into code.
 *
 *     [vbase/vcall offsets…]  offset_to_top  rtti       slot 0  slot 1 …
 *                             0              &typeinfo  &code
 *
 * Slot 0 is needed, as an exception table's catch entry is `{0, typeinfo}` too; so a class whose only
 * virtuals are its bases' is missed. A construction vtable has the same shape, so the caller chooses.
 */
fun Program.primaryRecordAt(addr: Address, header: Structure) = addr.takeIf(::isData)?.let { dataAt(it, header) }
    ?.takeIf { it.valueOf<Scalar>(Itanium.OFFSET_TO_TOP)?.value == 0L }
    ?.takeIf { it.valueOf<Address>("slot0")?.let(::isCode) == true }

/**
 * Where the record whose `offset_to_top` is at [top] starts: back past each word in front that reads as a
 * vbase or vcall offset (non-zero, under [MAX_VBASE_OFFSET], not into code). A 0 offset can't be told from
 * padding, so [RttiSymbols] corrects for it once the typeinfo says where the vbases are.
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

/** The header datatype at [start] whose rtti word is at [rttiSlot], or with the bare two-word header if null. */
private fun Program.headerAt(start: Address, rttiSlot: Address?): StructureDataType {
    val ptr = defaultPointerSize.toLong()
    val prefixWords = rttiSlot?.let { ((it - start) / ptr - 1).toInt() } ?: 0
    return dataTypeManager.vtableHeaderLayout(prefixWords)
}

/**
 * The record at [ztv], its header ending at the first word pointing at a typeinfo: a class with virtual
 * bases has vbase/vcall offsets before `offset_to_top`. Without one before the first slot, the header is
 * the bare two words, so the search never reaches the next record's.
 */
internal fun Program.itaniumVtableRecord(ztv: Address): VtableRecord {
    val ptr = defaultPointerSize.toLong()
    fun holdsTypeinfo(slot: Address) =
        pointerAt(slot)?.let { pointee -> symbolTable.getSymbols(pointee).any { it.isTypeinfo } } == true

    val rttiSlot = generateSequence(ztv) { it.add(ptr) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { holdsTypeinfo(it) || pointerAt(it)?.let(::isCode) != true }
        .firstOrNull(::holdsTypeinfo)
    return VtableRecord(ztv, headerAt(ztv, rttiSlot), Itanium)
}

/** A record in a vtable group, and the functions its slots point at. */
data class SubVtable(val record: VtableRecord, val targets: List<Address>) {
    fun endOfSlots(ptrSize: Int): Address = record.addressPoint.add(targets.size.toLong() * ptrSize)
}

/**
 * The record at [start], or null if it isn't in [rtti]'s group. One without slots still counts: a base
 * with no virtuals of its own still has a header, and the records after it would be lost.
 */
private fun Program.subVtableAt(start: Address, rtti: Address, construction: Boolean): SubVtable? =
    generateSequence(start) { it.add(defaultPointerSize.toLong()) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { pointerAt(it) == rtti || pointerAt(it)?.let(::isCode) != true }
        // The rtti word follows offset_to_top, so it is never the first.
        .firstOrNull { it > start && pointerAt(it) == rtti }
        ?.let { VtableRecord(start, headerAt(start, it), Itanium, internal = true, construction = construction) }
        ?.let { record -> SubVtable(record, record.slots(this)) }

/**
 * The secondary records after a primary whose slots end at [afterPrimary]. Nothing marks where a group ends,
 * so the walk goes on while the records share [rtti], and stops at one whose header holds the next
 * group's symbol, which can share it.
 */
fun Program.secondaryVtables(afterPrimary: Address, rtti: Address, construction: Boolean = false): List<SubVtable> =
    generateSequence(subVtableAt(afterPrimary, rtti, construction)) {
        subVtableAt(it.endOfSlots(defaultPointerSize), rtti, construction)
    }.takeWhile { sub -> !sub.record.opensGroup(this) }.toList()
