package ghistabs.cpp.abi.itanium

import ghidra.docking.settings.FormatSettingsDefinition
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghistabs.*
import ghistabs.cpp.Access
import ghistabs.cpp.BaseDecl
import ghistabs.cpp.ClassNaming

/**
 * The Itanium `__cxxabiv1` typeinfo layouts, after Ghidra's `RTTIGccClassRecoverer`, for the typeinfo
 * structs the stabs leave undefined. They stay out of the DTM, so [Reader] writes nothing; to lay one, go
 * through [resolveLayout], as resolving one afresh each time forks a `.conflict`.
 */
class Rtti(private val dtm: DataTypeManager) {
    private val pointerSize = dtm.dataOrganization.pointerSize
    private val bigEndian = dtm.dataOrganization.isBigEndian
    private val componentOffset = Itanium.vtablePrefixBytes(pointerSize)

    private fun struct(name: String) = StructureDataType(ClassNaming.classDataTypesRoot, name, 0, dtm)

    /**
     * The layout for the typeinfo type [name]: one of gcc's `__*_type_info_pseudo` structs, whose VMI one
     * carries its base count (`…_pseudo2`), or a `__cxxabiv1` class as the demangler names it, VMI's with
     * its declared one base. Null for any other name.
     */
    fun typeInfoLayout(name: String): StructureDataType? = with(Itanium) {
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
        // The fields [Reader] reads back.
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

    /**
     * Reads a class's bases off its typeinfo object (ABI §2.9.5), typed or not. Its vptr says which of the
     * three class layouts it has ([TypeinfoKind]); a vptr or base into a shared library is named by Ghidra's
     * external reference. gcc 2.x fills its typeinfo in at run time, so has nothing to read.
     */
    class Reader(private val program: Program) {
        /**
         * A direct base, and its own [typeinfo], possibly external. Its [offset] is the subobject's, or for a
         * virtual base where the vtable keeps that, from the address point (negative).
         */
        data class Base(
            val className: String,
            val typeinfo: Address,
            override val isVirtual: Boolean,
            override val access: Access,
            override val offset: Long = 0,
        ) : BaseDecl

        private val ptr = program.defaultPointerSize
        private val symtab = program.symbolTable

        private val layouts = Rtti(program.dataTypeManager)

        /** [zti]'s direct bases; null if it isn't a class typeinfo this can read. */
        fun basesOf(zti: Address): List<Base>? = runCatching {
            when (kindOf(zti)) {
                TypeinfoKind.CLASS -> emptyList()

                TypeinfoKind.SI -> program.dataAt(zti, layouts.siClassTi)?.get(BASE_TYPE)
                    ?.let { classAt(it.address) }
                    ?.let { (name, at) -> listOf(Base(name, at, isVirtual = false, access = Access.PUBLIC)) }

                TypeinfoKind.VMI -> vmiBases(zti)

                null -> null
            }
        }.getOrNull()

        /** The virtual bases whose offsets [zti]'s primary vtable keeps: its own, and its bases' at offset 0. */
        fun virtualBasesOf(zti: Address, depth: Int = 0): List<Base> =
            basesOf(zti).orEmpty().takeIf { depth < MAX_BASE_DEPTH }.orEmpty().flatMap { base ->
                when {
                    base.isVirtual -> listOf(base)
                    base.offset == 0L -> virtualBasesOf(base.typeinfo, depth + 1)
                    else -> emptyList()
                }
            }.distinctBy { it.className }

        fun structFor(zti: Address) = when (kindOf(zti)) {
            TypeinfoKind.CLASS -> layouts.classTi
            TypeinfoKind.SI -> layouts.siClassTi
            TypeinfoKind.VMI -> vmiCount(zti)?.takeIf { it in 1..MAX_BASES }?.let { layouts.vmiClassTypeInfo(it) }
            null -> null
        }

        private fun vmiCount(zti: Address) = program.dataAt(zti, layouts.vmiClassTypeInfo(1))
            ?.getScalar(NUM_BASES)?.unsignedValue?.toInt()

        private fun vmiBases(zti: Address): List<Base>? {
            val array = structFor(zti)?.let { program.dataAt(zti, it)?.get(BASES) } ?: return null
            return (0 until array.numComponents).map { i ->
                val entry = array[i] ?: return null
                val (name, at) = entry[BASE_TYPE_IN_ENTRY]?.let { classAt(it.address) } ?: return null
                Base(
                    name,
                    at,
                    isVirtual = entry.flag(IS_VIRTUAL),
                    access = if (entry.flag(IS_PUBLIC)) Access.PUBLIC else Access.PRIVATE,
                    offset = entry.getScalar(BASE_OFFSET)?.signedValue ?: return null,
                )
            }
        }

        // The vptr points two words past its vtable's `_ZTV` label.
        internal fun kindOf(zti: Address) =
            pointee(zti, Itanium.vtablePrefixBytes(ptr)) { it.vtableClass?.let(TypeinfoKind::ofVtableClass) }

        /** The class whose typeinfo the pointer at [at] points at, and where that typeinfo's symbol is. */
        private fun classAt(at: Address) = pointee(at, 0) { sym -> sym.typeinfoClass?.let { it to sym.address } }

        /**
         * [of] the first symbol the pointer at [at] refers to that it answers for: an external one by
         * Ghidra's reference, else one [back] bytes before its target. Not one at the target itself, which
         * in the EXTERNAL block can be the next import's label.
         */
        private fun <T : Any> pointee(at: Address, back: Long, of: (Symbol) -> T?): T? {
            val external = program.referenceManager.getReferencesFrom(at)
                .filter { it.isExternalReference || it.toAddress.isExternalAddress }
                .mapNotNull { symtab.getPrimarySymbol(it.toAddress) }
            val symbols = external.ifEmpty {
                val target = runCatching { program.pointerAt(at) }.getOrNull() ?: return null
                runCatching { symtab.getSymbols(target.subtract(back)).toList() }.getOrNull() ?: return null
            }
            return symbols.firstNotNullOfOrNull(of)
        }
    }
}

/** Shows this field in decimal, so an offset reads `-16`; [resolveLayout] carries the setting across. */
internal fun DataTypeComponent.showDecimal() = apply {
    if (!defaultSettings.isImmutableSettings) {
        FormatSettingsDefinition.DEF.setChoice(defaultSettings, FormatSettingsDefinition.DECIMAL)
    }
}
