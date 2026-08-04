package ghistabs.materialize.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.forceCreateData
import ghistabs.harvest.HarvestIndex
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Struct.Method
import ghistabs.parse.VirtKind

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

/**
 * Lay the Itanium vtable at [ztv] and return its address point. The header is
 * `[vbase/vcall offsets…] offset_to_top rtti` and the [vftable] function-pointer array + a
 * "vftable" symbol go at the address point — the value a `{vfptr}` holds — so a constructor's
 * `this->vfptr = &<Class>::vftable` resolves to a symbol, not a raw address.
 *
 * The address point is *not* a fixed `ztv + 2*ptrSize`: a class with a virtual base anywhere in
 * its hierarchy (anything derived from an iostream — `basic_istream` virtually inherits
 * `basic_ios`) has vbase/vcall-offset words before offset_to_top, so `_ZTV<class>` points that
 * many words early. Locate the rtti header word (the slot holding &`_ZTI<class>`, given as
 * [rttiAddr]); offset_to_top is the word before it, the address point the word after. When
 * [rttiAddr] is null (templates, missing rtti) or not found, fall back to the canonical 2*ptr
 * shape. The rtti pointee stays an untyped `void*` until backlog §24 wires it.
 */
fun Program.layVtable(
    ztv: Address,
    vftable: Structure,
    className: String,
    ns: Namespace,
    rttiAddr: Address?,
): Address {
    val ptr = defaultPointerSize.toLong()
    val rttiSlot = rttiAddr?.let { target ->
        generateSequence(ztv) { it.add(ptr) }
            .take(MAX_VTABLE_PREFIX_WORDS)
            .firstOrNull { readWord(it) == target.offset }
    }
    val topSlot = rttiSlot?.subtract(ptr) ?: ztv
    val rttiHeader = rttiSlot ?: ztv.add(ptr)
    val addressPoint = rttiSlot?.add(ptr) ?: ztv.add(Itanium.vtablePrefixBytes(defaultPointerSize))

    generateSequence(ztv) { it.add(ptr) }.takeWhile { it < topSlot }.forEach {
        forceCreateData(it, Itanium.offsetToTopType(defaultPointerSize))
        listing.setComment(it, CommentType.EOL, "vbase/vcall offset")
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
 * `__*_type_info_pseudo` records that are absent from the stabs on xapasmcsr etc.:
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
    fun typeInfoLayout(name: String): DataType? = when {
        name == Itanium.TYPE_INFO || name == Itanium.CLASS_TYPE_INFO || name == Itanium.CLASS_TYPE_INFO_PSEUDO ->
            classTypeInfoStructure

        name == Itanium.SI_CLASS_TYPE_INFO || name == Itanium.SI_CLASS_TYPE_INFO_PSEUDO -> siClassTypeInfoStructure

        name == Itanium.VMI_CLASS_TYPE_INFO -> vmiClassTypeInfoStructure(1)

        name.startsWith(Itanium.VMI_CLASS_TYPE_INFO_PSEUDO) ->
            name.removePrefix(Itanium.VMI_CLASS_TYPE_INFO_PSEUDO).toIntOrNull()?.let(::vmiClassTypeInfoStructure)

        else -> null
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
