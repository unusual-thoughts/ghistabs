package ghistabs.materialize.cpp.abi

import ghidra.program.model.data.*
import ghistabs.materialize.cpp.ClassNaming
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

    val classTypeInfoStructure by lazy { classTypeInfo().intoDtm() }
    val siClassTypeInfoStructure by lazy { siClassTypeInfo(classTypeInfoStructure).intoDtm() }
    val baseClassTypeInfoStructure by lazy { baseClassTypeInfo(classTypeInfoStructure).intoDtm() }

    fun vmiClassTypeInfoStructure(numBaseClasses: Int) =
        vmiClassTypeInfo(numBaseClasses, baseClassTypeInfoStructure).intoDtm()

    /**
     * The same layouts left out of the DTM, for reading a typeinfo object off memory ([RttiReader],
     * through [ghistabs.readAt]) without the write a resolve is.
     */
    inner class Unresolved {
        private val classTi = classTypeInfo()
        val siClassTypeInfo = siClassTypeInfo(classTi)
        private val baseClassTi = baseClassTypeInfo(classTi)

        fun vmiClassTypeInfo(numBaseClasses: Int) = vmiClassTypeInfo(numBaseClasses, baseClassTi)
    }

    private fun classTypeInfo() =
        StructureDataType(ClassNaming.classDataTypesRoot, "ClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, PointerDataType.dataType, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            isPackingEnabled = true
        }

    private fun siClassTypeInfo(classTi: DataType) =
        StructureDataType(ClassNaming.classDataTypesRoot, "SiClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(dtm.getPointer(classTi), BASE_TYPE, null)
            isPackingEnabled = true
        }

    // `__base_class_type_info`: `__offset_flags`' low bits are the `__offset_flags_masks` (ABI §2.9.5),
    // virtual (0x1) then public (0x2), and the offset sits above the low byte.
    private fun baseClassTypeInfo(classTi: DataType) =
        StructureDataType(ClassNaming.classDataTypesRoot, "BaseClassTypeInfoStructure", 0, dtm).apply {
            add(dtm.getPointer(classTi), "classTypeinfoPtr", null)

            val (offsetBitSize, dataType) = when (pointerSize) {
                8 -> 56 to LongLongDataType()
                else -> 24 to LongDataType()
            }

            if (bigEndian) {
                addBitField(dataType, offsetBitSize, "baseClassOffset", "baseClassOffset")
                addBitField(dataType, 1, IS_PUBLIC, IS_PUBLIC)
                addBitField(dataType, 1, IS_VIRTUAL, IS_VIRTUAL)
                addBitField(dataType, 6, "unused", "unused")
            } else {
                addBitField(dataType, 1, IS_VIRTUAL, IS_VIRTUAL)
                addBitField(dataType, 1, IS_PUBLIC, IS_PUBLIC)
                addBitField(dataType, 6, "unused", "unused")
                addBitField(dataType, offsetBitSize, "baseClassOffset", "baseClassOffset")
            }

            isPackingEnabled = true
        }

    private fun vmiClassTypeInfo(numBaseClasses: Int, baseClassTi: DataType) =
        StructureDataType(ClassNaming.classDataTypesRoot, "VmiClassTypeInfoStructure$numBaseClasses", 0, dtm).apply {
            add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(UnsignedIntegerDataType(), "flags", null)
            add(UnsignedIntegerDataType(), NUM_BASES, null)
            add(ArrayDataType(baseClassTi, numBaseClasses, baseClassTi.length), BASES, null)
            isPackingEnabled = true
        }

    companion object {
        // The fields [RttiReader] reads back.
        const val BASE_TYPE = "baseClassTypeInfoPtr"
        const val NUM_BASES = "numBaseClasses"
        const val BASES = "baseClassPtrArray"
        const val BASE_TYPE_IN_ENTRY = "classTypeinfoPtr"
        const val IS_VIRTUAL = "isVirtualBase"
        const val IS_PUBLIC = "isPublicBase"
    }
}
