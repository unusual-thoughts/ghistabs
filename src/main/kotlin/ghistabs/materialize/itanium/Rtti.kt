package ghistabs.materialize.itanium

import ghidra.program.model.data.*
import ghistabs.removePrefixOrNull

/**
 * Authoritative Itanium `__cxxabiv1` typeinfo struct layouts, adapted from Ghidra's
 * `RTTIGccClassRecoverer`. The implementation of last resort for the gcc-internal
 * `__*_type_info_pseudo` records that are absent from the stabs on most fixtures:
 */
class Rtti(private val dtm: DataTypeManager) {
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
