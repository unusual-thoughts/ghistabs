package ghistabs.cpp.abi

import ghidra.docking.settings.FormatSettingsDefinition
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghistabs.*
import ghistabs.cpp.ClassNaming
import ghistabs.parse.Access

/**
 * Authoritative Itanium `__cxxabiv1` typeinfo struct layouts, adapted from Ghidra's
 * `RTTIGccClassRecoverer`. The implementation of last resort for the gcc-internal
 * `__*_type_info_pseudo` records that are absent from the stabs on most fixtures.
 *
 * The layouts stay out of the DTM, so [Reader] reads a typeinfo object off memory without the write a
 * resolve is. Whatever puts one in the DTM goes through [resolveLayout], never `createData` directly: gcc
 * 3.4.5 emits every `_ZTI` as a per-CU COMDAT (`_ZTISt9exception` in 42 CUs), and an auto-named
 * PointerTypedef field never compares isEquivalent to its own resolved form, so resolving the layout
 * afresh each time forks a `.conflict` per reapply.
 */
class Rtti(private val dtm: DataTypeManager) {
    private val pointerSize = dtm.dataOrganization.pointerSize
    private val bigEndian = dtm.dataOrganization.isBigEndian
    private val componentOffset = Itanium.vtablePrefixBytes(pointerSize)

    private fun struct(name: String) = StructureDataType(ClassNaming.classDataTypesRoot, name, 0, dtm)

    /**
     * Reference layout for an Itanium typeinfo type named [name], keyed on both spellings it reaches
     * us by: gcc's internal `__*_type_info_pseudo` structs (from stab XRefs via `makePlaceholder`;
     * `__vmi_…_pseudo<N>` carries the real per-object base count N) and the abstract base classes
     * themselves as the demangler names them (`std::type_info`, `abi::__class_type_info`,
     * `abi::__si_class_type_info`, `abi::__vmi_class_type_info`, from libsupc++ symbols that carry no
     * stabs, via `DemanglerReplacer`). The abstract `__vmi_class_type_info` uses its declared
     * `__base_info[1]` shape — the class's own sizeof — vs the per-object pseudo's N. Null otherwise.
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

    /** `std::type_info` as a typeinfo that isn't a class's: a fundamental type's, an enum's, a function's. */
    val typeInfo = struct("TypeInfoStructure").apply {
        add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
        add(dtm.getPointer(CharDataType()), "typeinfoName", null)
        isPackingEnabled = true
    }

    /** `__pbase_type_info` as a pointer's: its cv-qualifier `__flags`, then the pointee's typeinfo. */
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

    // `__base_class_type_info`: `__offset_flags`' low bits are the `__offset_flags_masks` (ABI §2.9.5),
    // virtual (0x1) then public (0x2), and the offset sits above the low byte.
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

        // Arbitrary sanity bound: a garbage count must not read megabytes.
        const val MAX_BASES = 256

        // Bound on base chains walked: a typeinfo cycle in garbage must not recurse forever.
        const val MAX_BASE_DEPTH = 16
    }

    /**
     * Reads a class's direct bases off its Itanium `_ZTI` typeinfo object (ABI §2.9.5): [Rtti]'s
     * layouts, read off memory with [dataAt] whether or
     * not anything typed the object.
     *
     * The object's first word is the address point of one of three `__cxxabiv1` vtables, which says the
     * layout that follows: `__class_type_info` (no bases), `__si_class_type_info` (one public non-virtual
     * base at offset 0, then `__base_type`), or `__vmi_class_type_info` (`__flags`, `__base_count`, then
     * one `{__base_type, __offset_flags}` pair per base). In a dynamically linked binary that word is a
     * relocation to libstdc++, so it's named by the reference Ghidra made for it, as is each base's
     * typeinfo when it lives in a shared library (`std::exception`).
     *
     * gcc 2.x has nothing to read: `__ti<class>` sits in .bss, filled at run time by its `__tf<class>`
     * function (`__ti4Base` is `B` in hello_elf_gcc295's symbols), so only the stabs give its bases.
     */
    class Reader(private val program: Program) {
        /**
         * A direct base. [offset] is `__offset_flags`'s offset: where the base subobject sits in the class,
         * or for a virtual one where the vtable holds that, relative to the address point (negative).
         * [typeinfo] is where the base's own typeinfo is, to read its bases in turn: the symbol that named
         * it, which is in the EXTERNAL block for one a shared library defines.
         */
        data class Base(
            val className: String,
            val typeinfo: Address,
            val isVirtual: Boolean,
            val access: Access,
            val offset: Long = 0,
        )

        private val ptr = program.defaultPointerSize
        private val symtab = program.symbolTable

        private val layouts = Rtti(program.dataTypeManager)

        /** Null when [zti] isn't a class typeinfo this can read, rather than a class with no bases. */
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

        /**
         * [zti]'s virtual bases whose offsets its primary vtable keeps, each with its vtable offset: its own,
         * and those of its primary chain (the non-virtual bases at 0, which share that vtable).
         */
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

        // The vptr is the vtable's address point, two words past its `_ZTV` label.
        internal fun kindOf(zti: Address) =
            pointee(zti, Itanium.vtablePrefixBytes(ptr)) { it.vtableClass?.let(TypeinfoKind::ofVtableClass) }

        /** The class whose typeinfo the pointer at [at] points at, and where that typeinfo's symbol is. */
        private fun classAt(at: Address) = pointee(at, 0) { sym -> sym.typeinfoClass?.let { it to sym.address } }

        /**
         * [of] the first symbol the pointer at [at] refers to that it answers for: an external one by
         * Ghidra's reference to it, else a label [back] bytes before the address the pointer holds. Never
         * at that address itself when [back] isn't 0: the ELF loader packs its stand-ins for external
         * objects into the EXTERNAL block, so a `__class_type_info` vtable's address point is where
         * `__si_class_type_info`'s label sits (hello_elf_gcc12).
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

/**
 * Show [this] field's integer value in decimal: an offset reads as `-16`, not `0xfffffff0`. A layout's
 * component settings stay behind when the DTM resolves it, so [resolveLayout] copies them across.
 */
internal fun DataTypeComponent.showDecimal() = apply {
    if (!defaultSettings.isImmutableSettings) {
        FormatSettingsDefinition.DEF.setChoice(defaultSettings, FormatSettingsDefinition.DECIMAL)
    }
}
