package ghicpp.abi.itanium

import ghicpp.ClassNaming
import ghidra.docking.settings.FormatSettingsDefinition
import ghidra.program.model.data.*
import ghidrakt.removePrefixOrNull

/**
 * The structs of the Itanium `__cxxabiv1` typeinfo objects, after Ghidra's `RTTIGccClassRecoverer`, for
 * the typeinfo types the stabs leave undefined. They stay out of the DTM, so [TypeinfoReader] writes
 * nothing; to lay one, go through [resolveLayout], as resolving one afresh each time forks a `.conflict`.
 */
class Typeinfo(private val dtm: DataTypeManager) {
    private val pointerSize = dtm.dataOrganization.pointerSize
    private val bigEndian = dtm.dataOrganization.isBigEndian
    private val componentOffset = Itanium.vtablePrefixBytes(pointerSize)

    private fun struct(name: String) = StructureDataType(ClassNaming.classDataTypesRoot, name, 0, dtm)

    /**
     * The struct for the typeinfo type [name]: one of gcc's `__*_type_info_pseudo` structs, whose VMI one
     * carries its base count (`…_pseudo2`), or a `__cxxabiv1` class as the demangler names it, VMI's with
     * its declared one base. Null for any other name.
     */
    fun structFor(name: String): StructureDataType? = with(Itanium) {
        when (name) {
            TYPE_INFO, CLASS_TYPE_INFO, CLASS_TYPE_INFO_PSEUDO -> classTi
            SI_CLASS_TYPE_INFO, SI_CLASS_TYPE_INFO_PSEUDO -> siClassTi
            VMI_CLASS_TYPE_INFO -> vmiClassTypeInfo(1)
            POINTER_TYPE_INFO_PSEUDO -> pointerTi
            POINTER_TO_MEMBER_TYPE_INFO_PSEUDO -> pointerToMemberTi
            in NAME_ONLY_TYPE_INFO_PSEUDOS -> typeInfo
            else -> name.removePrefixOrNull(VMI_CLASS_TYPE_INFO_PSEUDO)?.toIntOrNull()?.let(::vmiClassTypeInfo)
        }
    }

    val classTi = struct("ClassTypeInfoStructure").apply {
        add(PointerTypedef(null, PointerDataType.dataType, -1, dtm, componentOffset), "classTypeinfoPtr", null)
        add(dtm.getPointer(CharDataType()), "typeinfoName", null)
        isPackingEnabled = true
    }
    val siClassTi = struct("SiClassTypeInfoStructure").apply {
        add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
        add(dtm.getPointer(CharDataType()), "typeinfoName", null)
        add(dtm.getPointer(classTi), BASE_TYPE, null)
        isPackingEnabled = true
    }

    /** A typeinfo that is no class's: a fundamental type's, an enum's, a function's. */
    val typeInfo = struct("TypeInfoStructure").apply {
        add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
        add(dtm.getPointer(CharDataType()), "typeinfoName", null)
        isPackingEnabled = true
    }

    /** A pointer's typeinfo: its cv-qualifier `__flags`, then the pointee's typeinfo. */
    val pointerTi = struct("PointerTypeInfoStructure").apply {
        add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
        add(dtm.getPointer(CharDataType()), "typeinfoName", null)
        add(UnsignedIntegerDataType(), "flags", null)
        add(dtm.getPointer(typeInfo), "pointee", null)
        isPackingEnabled = true
    }

    /** A member pointer's: [pointerTi] and the class the member is of. */
    val pointerToMemberTi = struct("PointerToMemberTypeInfoStructure").apply {
        for (c in pointerTi.definedComponents) add(c.dataType, c.fieldName, null)
        add(dtm.getPointer(classTi), "context", null)
        isPackingEnabled = true
    }

    // `__base_class_type_info` (ABI §2.9.5): `__offset_flags` has virtual (0x1) and public (0x2) in its low
    // byte and the offset above it.
    val bClassTi = struct("BaseClassTypeInfoStructure").apply {
        add(dtm.getPointer(classTi), "classTypeinfoPtr", null)

        val (offsetBitSize, dataType) = when (pointerSize) {
            8 -> 56 to LongLongDataType()
            else -> 24 to LongDataType()
        }

        if (bigEndian) {
            addBitField(dataType, offsetBitSize, BASE_OFFSET, null).showDecimal()
            addBitField(dataType, 1, IS_PUBLIC, null)
            addBitField(dataType, 1, IS_VIRTUAL, null)
            addBitField(dataType, 6, "unused", null)
        } else {
            addBitField(dataType, 1, IS_VIRTUAL, null)
            addBitField(dataType, 1, IS_PUBLIC, null)
            addBitField(dataType, 6, "unused", null)
            addBitField(dataType, offsetBitSize, BASE_OFFSET, null).showDecimal()
        }

        isPackingEnabled = true
    }

    fun vmiClassTypeInfo(numBaseClasses: Int) = struct("VmiClassTypeInfoStructure$numBaseClasses").apply {
        add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
        add(dtm.getPointer(CharDataType()), "typeinfoName", null)
        add(UnsignedIntegerDataType(), "flags", null)
        add(UnsignedIntegerDataType(), NUM_BASES, null)
        add(ArrayDataType(bClassTi, numBaseClasses, bClassTi.length), BASES, null)
        isPackingEnabled = true
    }

    companion object {
        // The fields [TypeinfoReader] reads back.
        const val BASE_TYPE = "baseClassTypeInfoPtr"
        const val NUM_BASES = "numBaseClasses"
        const val BASES = "baseClassPtrArray"
        const val BASE_OFFSET = "baseClassOffset"
        const val BASE_TYPE_IN_ENTRY = "classTypeinfoPtr"
        const val IS_VIRTUAL = "isVirtualBase"
        const val IS_PUBLIC = "isPublicBase"

        // Bounds a garbage base count.
        const val MAX_BASES = 256

        // Bounds a walk up the bases, against a cycle in garbage.
        const val MAX_BASE_DEPTH = 16
    }

    /** The `__cxxabiv1` class a class's typeinfo object is an instance of. */
    enum class Kind(private val abiClass: String) {
        /** `__class_type_info`: no bases. */
        CLASS(Itanium.CLASS_TYPE_INFO),

        /** `__si_class_type_info`: one public, non-virtual base at offset 0. */
        SI(Itanium.SI_CLASS_TYPE_INFO),

        /** `__vmi_class_type_info`: anything else, each base with its own offset and flags. */
        VMI(Itanium.VMI_CLASS_TYPE_INFO),
        ;

        companion object {
            /** The kind whose vtable is [vtableClass]'s, or null for any other class's. */
            fun ofVtableClass(vtableClass: String) = entries.firstOrNull {
                "${Itanium.ABI_NAMESPACE}::${it.abiClass}" == vtableClass
            }
        }
    }
}

/** Shows this field in decimal, so an offset reads `-16`; [resolveLayout] carries the setting across. */
internal fun DataTypeComponent.showDecimal() = apply {
    if (!defaultSettings.isImmutableSettings) {
        FormatSettingsDefinition.DEF.setChoice(defaultSettings, FormatSettingsDefinition.DECIMAL)
    }
}
