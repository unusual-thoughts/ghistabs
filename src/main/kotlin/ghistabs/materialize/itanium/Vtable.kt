package ghistabs.materialize.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.forceCreateData
import ghistabs.harvest.HarvestIndex
import ghistabs.importer.AddressResolver
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Struct.Method
import ghistabs.parse.VirtKind
import ghistabs.removePrefixOrNull

/**
 * Collects a class's full vtable slot list from its inheritance chain and orders it by the
 * stab-declared slot offset. The walk gathers virtuals bases-first so a derived override (matched
 * by name) replaces the inherited slot and its offset wins; output order is set by the final sort,
 * not the walk. Override matching is by name only — fine for the non-overloaded gcc 3.4.4 corpus.
 */
class Virtuals(
    private val index: HarvestIndex,
    private val table: MutableList<Method<GlobalTypeId>> = mutableListOf(),
    private val visited: MutableSet<TypeDecl.Struct<GlobalTypeId>> = mutableSetOf(),
) {
    private fun walkBases(cls: TypeDecl.Struct<GlobalTypeId>) {
        for (base in cls.bases) {
            index.resolveBaseAstStatic(base.type)?.takeIf { visited.add(it) }?.let { collectAll(it) }
        }
    }

    private fun collectAll(cls: TypeDecl.Struct<GlobalTypeId>) {
        walkBases(cls)
        for (m in cls.methods.filter { it.virt == VirtKind.VIRTUAL }) {
            val idx = table.indexOfFirst { it.name == m.name }
            if (idx >= 0) table[idx] = m else table += m
        }
    }

    fun process(cls: TypeDecl.Struct<GlobalTypeId>): List<Method<GlobalTypeId>> {
        collectAll(cls)
        return table.sortedBy { it.vtableOffsetBits!! }
    }
}

/** Upper bound on vbase/vcall-offset words scanned before giving up on locating the rtti header. */
private const val MAX_VTABLE_PREFIX_WORDS = 64

/** Pointer-sized word at [a] from initialized memory (endianness-aware), or null if unmapped. */
private fun Program.readWord(a: Address): Long? = runCatching {
    if (defaultPointerSize == 8) memory.getLong(a) else memory.getInt(a).toLong() and 0xFFFFFFFFL
}.getOrNull()

/** The word at [a] read as an address, or null if it is unmapped or does not point into executable
 *  memory. The one test that separates a vtable's function pointers from its header words — both
 *  scans below turn on it, and neither can use symbol presence, which auto-analysis sprays `PTR_`
 *  labels across. */
private fun Program.codeTargetAt(a: Address, resolver: AddressResolver): Address? =
    readWord(a)?.let(resolver::buildAddress)?.takeIf { memory.getBlock(it)?.isExecute == true }

/** Where the three fixed words of an Itanium vtable record sit — see [vtableShape]. */
data class VtableShape(val topSlot: Address, val rttiHeader: Address, val addressPoint: Address)

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
    return if (i < vcalls) "vcall offset" else "vbase offset: ${virtualBases[i - vcalls]}"
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
 */
fun Program.vtableShape(ztv: Address, resolver: AddressResolver): VtableShape {
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
    return VtableShape(
        topSlot = rttiSlot?.subtract(ptr) ?: ztv,
        rttiHeader = rttiSlot ?: ztv.add(ptr),
        addressPoint = rttiSlot?.add(ptr) ?: ztv.add(Itanium.vtablePrefixBytes(defaultPointerSize)),
    )
}

/**
 * Addresses the function-pointer array at [addressPoint] holds, in slot order. Nothing records its
 * length, so it ends where the words stop pointing into executable memory — at the next record's
 * `offset_to_top` (0) or rtti pointer (into .data). Only used where no stab method list gives the
 * count; a harvested class takes its slots from its own virtuals.
 */
fun Program.vtableSlotTargets(addressPoint: Address, resolver: AddressResolver): List<Address> =
    generateSequence(addressPoint) { it.add(defaultPointerSize.toLong()) }
        .map { codeTargetAt(it, resolver) }
        .takeWhile { it != null }
        .filterNotNull()
        .toList()

/**
 * Lay the Itanium vtable record at [ztv], whose geometry is [shape], and return its address point.
 * The header is `[vbase/vcall offsets…] offset_to_top rtti` and the [vftable] function-pointer
 * array + a "vftable" symbol go at the address point — the value a `{vfptr}` holds — so a
 * constructor's `this->vfptr = &<Class>::vftable` resolves to a symbol, not a raw address.
 * The rtti pointee stays an untyped `void*` until backlog §24 wires it.
 */
fun Program.layVtable(
    ztv: Address,
    shape: VtableShape,
    vftable: Structure,
    className: String,
    ns: Namespace,
    virtualBases: List<String> = emptyList(),
): Address {
    val ptr = defaultPointerSize.toLong()
    val (topSlot, rttiHeader, addressPoint) = shape

    val prefix = generateSequence(ztv) { it.add(ptr) }.takeWhile { it < topSlot }.toList()
    prefix.forEachIndexed { i, slot ->
        forceCreateData(slot, Itanium.offsetToTopType(defaultPointerSize))
        listing.setComment(slot, CommentType.EOL, prefixKind(i, prefix.size, virtualBases))
    }
    forceCreateData(topSlot, Itanium.offsetToTopType(defaultPointerSize))
    listing.setComment(topSlot, CommentType.EOL, "${Itanium.OFFSET_TO_TOP} (to top of complete object)")
    forceCreateData(rttiHeader, PointerDataType(dataTypeManager))
    listing.setComment(rttiHeader, CommentType.EOL, "${Itanium.RTTI}: ${Itanium.zti(className)} typeinfo")
    forceCreateData(addressPoint, vftable)
    symbolTable.createLabel(addressPoint, Itanium.VFTABLE, ns, SourceType.IMPORTED)
    return addressPoint
}

/**
 * Authoritative Itanium `__cxxabiv1` typeinfo struct layouts, adapted from Ghidra's
 * `RTTIGccClassRecoverer`. The implementation of last resort for the gcc-internal
 * `__*_type_info_pseudo` records that are absent from the stabs on most fixtures:
 */
class RttiStructs(private val dtm: DataTypeManager) {
    private val pointerSize = dtm.dataOrganization.pointerSize
    private val bigEndian = dtm.dataOrganization.isBigEndian
    private val componentOffset = Itanium.vtablePrefixBytes(pointerSize)

    /**
     * Reference layout for an Itanium typeinfo type named [name], keyed on both spellings it reaches
     * us by: gcc's internal `__*_type_info_pseudo` structs (from stab XRefs via `makePlaceholder`;
     * `__vmi_…_pseudo<N>` carries the real per-object base count N) and the abstract base classes
     * themselves as the demangler names them (`std::type_info`, `abi::__class_type_info`,
     * `abi::__si_class_type_info`, `abi::__vmi_class_type_info`, from libsupc++ symbols that carry no
     * stabs, via `DemanglerReplacer`). The abstract `__vmi_class_type_info` uses its declared
     * `__base_info[1]` shape — the class's own sizeof — vs the per-object pseudo's N. Null otherwise.
     */
    fun typeInfoLayout(name: String): DataType? = with(Itanium) {
        when (name) {
            TYPE_INFO, CLASS_TYPE_INFO, CLASS_TYPE_INFO_PSEUDO -> classTypeInfoStructure
            SI_CLASS_TYPE_INFO, SI_CLASS_TYPE_INFO_PSEUDO -> siClassTypeInfoStructure
            VMI_CLASS_TYPE_INFO -> vmiClassTypeInfoStructure(1)
            else -> name.removePrefixOrNull(VMI_CLASS_TYPE_INFO_PSEUDO)?.toIntOrNull()?.let(::vmiClassTypeInfoStructure)
        }
    }

    // Resolve each layout into the DTM once and hand out the resolved, DTM-resident type. gcc 3.4.5
    // emits every _ZTI typeinfo global as a per-CU COMDAT (e.g. _ZTISt9exception in 42 CUs), so the
    // same layout is applied to that address dozens of times. Handing createData the unresolved
    // template each time re-resolves it, and an auto-named PointerTypedef field never compares
    // isEquivalent to its own resolved form, so DEFAULT_HANDLER forks `.conflict` on every reapply.
    // getDataType-first also makes re-imports idempotent. Mirrors DataTypeManager.stabRecordDataType.
    private fun StructureDataType.intoDtm(): DataType =
        dtm.getDataType(categoryPath, name) ?: dtm.resolve(this, DataTypeConflictHandler.KEEP_HANDLER)

    val classTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "ClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, PointerDataType.dataType, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            isPackingEnabled = true
        }.intoDtm()
    }

    val siClassTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "SiClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(dtm.getPointer(classTypeInfoStructure), "baseClassTypeInfoPtr", null)
            isPackingEnabled = true
        }.intoDtm()
    }

    val baseClassTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "BaseClassTypeInfoStructure", 0, dtm).apply {
            add(dtm.getPointer(classTypeInfoStructure), "classTypeinfoPtr", null)

            val (offsetBitSize, dataType) = when (pointerSize) {
                8 -> 56 to LongLongDataType()
                else -> 24 to LongDataType()
            }

            if (bigEndian) {
                addBitField(dataType, offsetBitSize, "baseClassOffset", "baseClassOffset")
                addBitField(dataType, 1, "isPublicBase", "isPublicBase")
                addBitField(dataType, 1, "isVirtualBase", "isVirtualBase")
                addBitField(dataType, 6, "unused", "unused")
            } else {
                addBitField(dataType, 1, "isVirtualBase", "isVirtualBase")
                addBitField(dataType, 1, "isPublicBase", "isPublicBase")
                addBitField(dataType, 6, "unused", "unused")
                addBitField(dataType, offsetBitSize, "baseClassOffset", "baseClassOffset")
            }

            isPackingEnabled = true
        }.intoDtm()
    }

    fun vmiClassTypeInfoStructure(numBaseClasses: Int) =
        StructureDataType(Itanium.classDataTypesRoot, "VmiClassTypeInfoStructure$numBaseClasses", 0, dtm).apply {
            add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(UnsignedIntegerDataType(), "flags", null)
            add(UnsignedIntegerDataType(), "numBaseClasses", null)
            add(
                ArrayDataType(baseClassTypeInfoStructure, numBaseClasses, baseClassTypeInfoStructure.length),
                "baseClassPtrArray",
                null,
            )
            isPackingEnabled = true
        }.intoDtm()
}
