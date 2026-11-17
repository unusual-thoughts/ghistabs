package ghicpp.abi

import ghicpp.ClassNaming
import ghicpp.CxxAbi
import ghicpp.VtableRecord
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.itanium.TypeinfoReader
import ghicpp.abi.itanium.startsVtableGroup
import ghicpp.abi.itanium.vtableOffsetField
import ghicpp.abi.msvc.Msvc
import ghicpp.abi.msvc.msvcSubobjectOffset
import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidrakt.*

/**
 * The vbase offset this record keeps for virtual [base], at the header word [base]'s typeinfo offset
 * names, which is commented with [base]'s name. Null if that word is not in the header.
 */
fun VtableRecord.vbaseOffset(program: Program, base: TypeinfoReader.Base) = vtableOffsetField(
    ((addressPoint + base.offset - address) / program.defaultPointerSize).toInt(),
).let { field ->
    fieldAddress(field)?.let { program.listing.setComment(it, CommentType.EOL, "${base.className} vbase offset") }
    readHeader(program)?.getScalar(field)?.signedValue
}

/** The typeinfo the rtti word points at. */
fun VtableRecord.rttiOf(program: Program): Address? = readHeader(program)?.valueOf<Address>(Itanium.RTTI)

/**
 * What header word [i] of [total] holds: vcall offsets, then one vbase offset per virtual base
 * (§2.5.2). Unsplit when the class states no virtual bases, or more than the words.
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

/** Whether a vtable group's symbol sits on a header word: a walk through secondaries has left its group. */
fun VtableRecord.opensGroup(program: Program): Boolean =
    generateSequence(address) { it.add(program.defaultPointerSize.toLong()) }
        .takeWhile { it < addressPoint }
        .any { at -> program.symbolTable.getSymbols(at).any { startsVtableGroup(it.name) } }

/** The functions the slots point at, in order ([functionSlots]). */
fun VtableRecord.slots(program: Program): List<Address> = program.functionSlots(addressPoint, abi).toList()

/**
 * The rtti word's comment: the typeinfo symbol actually there, its linkage name over Ghidra's `typeinfo`
 * label, and only then [Itanium.zti]'s guess, which misses abbreviations such as `_ZTISi`.
 */
private fun VtableRecord.rttiComment(program: Program, className: String): String {
    val name = rttiOf(program)
        ?.let { program.symbolTable.getSymbols(it).map { s -> s.name } }
        ?.let { names -> names.firstOrNull(Itanium::looksLikeZti) ?: names.firstOrNull() }
        ?: Itanium.zti(className)
    return "$name typeinfo"
}

/**
 * Labels and lays this record as [ns]'s table serving [base], and returns its address point, where the
 * [vftable] struct and the `vftable` label go. An Itanium header is laid in front, each word commented
 * with what it holds for [ns], whose [virtualBases] name its vbase offsets. A gcc 2.x record
 * is only labelled.
 */
fun VtableRecord.lay(
    registry: DtmRegistry,
    program: Program,
    vftable: Structure?,
    ns: Namespace,
    base: String? = null,
    virtualBases: List<String> = emptyList(),
    source: SourceType = SourceType.IMPORTED,
): Address {
    val vftableLabel = ClassNaming.vftableLabel(internal, construction, base)
    // gcc 2.x declares the record itself (`__vtbl_ptr_type __vt_9TiXmlNode[20]`), which knows its length
    // better than anything here, and a virtual call resolves off the vptr's type, not the data there.
    if (header == null) {
        program.listing.setComment(address, CommentType.EOL, "gcc 2.x vtable: reserved entry, then the slots")
        program.labelVtable(address, vftableLabel, ns, source)
        return address
    }

    program.labelVtable(address, ClassNaming.vtableLabel(internal, construction), ns, source)
    program.forceCreateData(address, registry.resolveLayout(header))
    for (i in 0 until prefixWords) {
        fieldAddress(vtableOffsetField(i))?.let {
            program.listing.setComment(it, CommentType.EOL, prefixKind(i, prefixWords, virtualBases))
        }
    }
    fieldAddress(Itanium.RTTI)?.let {
        program.listing.setComment(it, CommentType.EOL, rttiComment(program, ns.getName(true)))
    }
    vftable?.let { program.forceCreateData(addressPoint, it) }
    program.labelVtable(addressPoint, vftableLabel, ns, source)
    return addressPoint
}

/** gcc's two destructor entries, complete and deleting: the only slots it leaves null. */
const val DESTRUCTOR_SLOTS = 2

/**
 * The functions the slots of the [abi]'s vtable whose address point is [at] point at, in order. Nothing
 * records how many there are, so they end at the first entry that isn't code ([isSlotCode]) or an imported
 * function [imported] takes. Up to two nulls count when a function follows: gcc 12 leaves an abstract
 * class's destructor slots 0.
 */
internal fun Program.functionSlots(at: Address, abi: CxxAbi, imported: (Function) -> Boolean = { true }) = sequence {
    val nulls = mutableListOf<Address>()
    for (pfn in abi.slotOffsets(defaultPointerSize).map(at::add)) {
        val target = pointerAt(pfn) ?: break
        when {
            target.offset == 0L && nulls.size < DESTRUCTOR_SLOTS -> nulls += target

            isSlotCode(pfn, target) || importedFunction(pfn, target)?.let(imported) == true -> {
                yieldAll(nulls)
                yield(target)
                nulls.clear()
            }

            else -> break
        }
    }
}

/**
 * Whether the slot at [pfn] points at code: executable memory, and not back into the read-only block the
 * slot itself is in. gcc 3.3–4.9 link `.rodata` into the R-X text segment, so the vtables, VTTs and
 * typeinfos there are executable too: past a table's last slot, the next record's `offset_to_top` 0 reads
 * as a null slot, and its typeinfo pointer, or a VTT's pointers at other tables, as functions. An a.out
 * object loads its text and data as one writable block, where a slot does point into its own block.
 */
internal fun Program.isSlotCode(pfn: Address, target: Address): Boolean =
    isCode(target) && memory.getBlock(pfn).let { it == null || it.isWrite || it != memory.getBlock(target) }

/**
 * The program's own function the slot pointing at [at] holds, past a jump stub, and made where code has
 * none ([functionAtOrCreate]); not an import nor [abi]'s pure virtual stub ([CxxAbi.isPureVirtualStub]).
 */
fun Program.slotFunction(at: Address, abi: CxxAbi): Function? {
    val func = functionAtOrCreate(at) ?: return null
    val target = if (func.isThunk) func.getThunkedFunction(true) else func
    return target?.takeUnless { it.isExternal || abi.isPureVirtualStub(it.name) }
}

/**
 * The imported function whose thunk is at [target], if [pfn] is relocated against it. Data imports share
 * the EXTERNAL block, so the thunk alone doesn't say: a typeinfo's vptr can land on one.
 */
fun Program.importedFunction(pfn: Address, target: Address): Function? {
    val thunk = functionManager.getFunctionAt(target)?.takeIf { it.isThunk } ?: return null
    return thunk.takeIf { relocationTable.getRelocations(pfn).any { it.symbolName == thunk.name } }
}

/** Labels [at], raising an existing label to [SourceType.IMPORTED], which is what [isVtableClaimed] reads. */
private fun Program.labelVtable(at: Address, label: String, ns: Namespace, source: SourceType) {
    val sym = symbolTable.createLabel(at, label, ns, source)
    if (source == SourceType.IMPORTED && sym.source != source) sym.source = source
}

/** Renames [ns]'s [from] label at [at] to [to], or drops it for a [to] already there. */
fun Program.renameVtableLabel(at: Address, from: String, to: String, ns: Namespace) {
    if (from == to) return
    val here = symbolTable.getSymbols(at).filter { it.parentNamespace == ns }
    val old = here.firstOrNull { it.name == from } ?: return
    when (val existing = here.firstOrNull { it.name == to }) {
        null -> old.setName(to, old.source)

        else -> {
            if (old.source == SourceType.IMPORTED) existing.source = SourceType.IMPORTED
            old.delete()
        }
    }
}

/**
 * Whether [label], one of a class's vftable labels, marks its primary table. Once there are several, the
 * record says: an Itanium primary's header is `vtable`, not `internal_vtable`; a gcc 2.x primary has its
 * class's own `_vt` symbol; an MSVC one's complete object locator gives offset 0.
 */
fun Program.isPrimaryVftable(label: Symbol): Boolean =
    msvcSubobjectOffset(label.address)?.let { it == 0 } ?: when (label.name) {
        ClassNaming.VFTABLE -> true

        ClassNaming.vftableLabel(internal = true) -> false

        else -> listing.getDataBefore(label.address)?.takeIf { it.maxAddress.next() == label.address }
            ?.let { symbolTable.getSymbols(it.address) }.orEmpty()
            .any { it.name == ClassNaming.VTABLE && it.parentNamespace == label.parentNamespace } ||
            symbolTable.getSymbols(label.address).any {
                CxxAbi.ofVtableSymbol(it.name)?.isPrimaryVtable(it.name) == true
            }
    }

/**
 * The struct of the table [label] marks: the one laid there, or for gcc 2.x, which lays none, the one
 * [ClassNaming.vftableName] names for a primary among as many tables as its class has labels:
 * `<leaf>_vftable_for_<Base>` for `vftable_for_<Base>`, and for `vftable`, `<leaf>_vftable` when it is the
 * class's only table, else Ghidra's numbered fallback.
 */
fun Program.vftableStructAt(label: Symbol): Structure? {
    (listing.getDataAt(label.address)?.dataType as? Structure)?.takeIf { "_${ClassNaming.VFTABLE}" in it.name }
        ?.let { return it }
    val base = when {
        label.name.startsWith(ClassNaming.VFTABLE_FOR) -> label.name.removePrefix(ClassNaming.VFTABLE_FOR)
        label.name == ClassNaming.VFTABLE -> null
        else -> return null
    }
    val ns = label.parentNamespace
    val count = symbolTable.getSymbols(ns).iterator().asSequence().count { ClassNaming.isClassVftableLabel(it.name) }
    val category = ClassNaming.vftableCategory(ns)
    // The leaf may spell the class otherwise than the namespace does, so the name is matched as a suffix.
    val suffix = ClassNaming.vftableName(category.at("_${ClassNaming.VFTABLE}"), 0, count, base)
    return dataTypeManager.getCategory(category)?.dataTypes.orEmpty().filterIsInstance<Structure>()
        .firstOrNull { it.name.endsWith(suffix) }
}

/**
 * Whether the stabs import already laid [record]: an [SourceType.IMPORTED] vftable label at its address
 * point. A sweep's labels are [SourceType.ANALYSIS], so a later sweep lays the table again.
 */
fun Program.isVtableClaimed(record: VtableRecord): Boolean = symbolTable.getSymbols(record.addressPoint)
    .any { it.source == SourceType.IMPORTED && ClassNaming.isClassVftableLabel(it.name) }

/**
 * The record at [at] as [abi] reads it; null where memory holds no bytes, as at the EXTERNAL label of a
 * vtable another object defines.
 */
fun Program.definedVtableRecord(at: Address, abi: CxxAbi): VtableRecord? =
    at.takeIf(::isInitialized)?.let { abi.recordAt(this, it) }
