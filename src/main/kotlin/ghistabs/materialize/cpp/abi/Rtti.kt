package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghistabs.*
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.parse.Access

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

    /**
     * The layouts left out of the DTM, for reading a typeinfo object off memory ([Reader], through
     * [ghistabs.readAt]) without the write a resolve is. The `*Structure`s below are these resolved.
     */
    inner class Unresolved {
        val classTi = StructureDataType(ClassNaming.classDataTypesRoot, "ClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, PointerDataType.dataType, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            isPackingEnabled = true
        }
        val siClassTi = StructureDataType(ClassNaming.classDataTypesRoot, "SiClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(dtm.getPointer(classTi), BASE_TYPE, null)
            isPackingEnabled = true
        }

        // `__base_class_type_info`: `__offset_flags`' low bits are the `__offset_flags_masks` (ABI §2.9.5),
        // virtual (0x1) then public (0x2), and the offset sits above the low byte.
        val bClassTi = StructureDataType(ClassNaming.classDataTypesRoot, "BaseClassTypeInfoStructure", 0, dtm).apply {
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

        fun vmiClassTypeInfo(numBaseClasses: Int) = StructureDataType(
            ClassNaming.classDataTypesRoot,
            "VmiClassTypeInfoStructure$numBaseClasses",
            0,
            dtm,
        ).apply {
            add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(UnsignedIntegerDataType(), "flags", null)
            add(UnsignedIntegerDataType(), NUM_BASES, null)
            add(ArrayDataType(bClassTi, numBaseClasses, bClassTi.length), BASES, null)
            isPackingEnabled = true
        }
    }

    val unresolved by lazy { Unresolved() }

    // Resolving a layout resolves the unresolved ones it points at too, onto the copy already in the
    // DTM when there is one (KEEP_HANDLER).
    val classTypeInfoStructure by lazy { unresolved.classTi.intoDtm() }
    val siClassTypeInfoStructure by lazy { unresolved.siClassTi.intoDtm() }
    val baseClassTypeInfoStructure by lazy { unresolved.bClassTi.intoDtm() }

    fun vmiClassTypeInfoStructure(numBaseClasses: Int) = unresolved.vmiClassTypeInfo(numBaseClasses).intoDtm()

    companion object {
        // The fields [Reader] reads back.
        const val BASE_TYPE = "baseClassTypeInfoPtr"
        const val NUM_BASES = "numBaseClasses"
        const val BASES = "baseClassPtrArray"
        const val BASE_TYPE_IN_ENTRY = "classTypeinfoPtr"
        const val IS_VIRTUAL = "isVirtualBase"
        const val IS_PUBLIC = "isPublicBase"

        // Arbitrary sanity bound: a garbage count must not read megabytes.
        const val MAX_BASES = 256
    }

    /**
     * Reads a class's direct bases off its Itanium `_ZTI` typeinfo object (ABI §2.9.5): [Rtti]'s
     * layouts, [Unresolved] so nothing lands in the DTM, read off memory with [readAt] whether or
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
        data class Base(val className: String, val isVirtual: Boolean, val access: Access)

        private val ptr = program.defaultPointerSize
        private val symtab = program.symbolTable

        private val layouts = Rtti(program.dataTypeManager).unresolved

        /** Null when [zti] isn't a class typeinfo this can read, rather than a class with no bases. */
        fun basesOf(zti: Address): List<Base>? = runCatching {
            when (kindOf(zti)) {
                TypeinfoKind.CLASS -> emptyList()

                TypeinfoKind.SI -> program.readAt(zti, layouts.siClassTi)?.get(BASE_TYPE)
                    ?.let { classAt(it.address) }
                    ?.let { listOf(Base(it, isVirtual = false, access = Access.PUBLIC)) }

                TypeinfoKind.VMI -> vmiBases(zti)

                null -> null
            }
        }.getOrNull()

        private fun vmiBases(zti: Address): List<Base>? {
            val count = program.readAt(zti, layouts.vmiClassTypeInfo(1))
                ?.getScalar(NUM_BASES)?.unsignedValue?.toInt()
            if (count == null || count !in 1..MAX_BASES) return null
            val array = program.readAt(zti, layouts.vmiClassTypeInfo(count))?.get(BASES) ?: return null
            return (0 until array.numComponents).map { i ->
                val entry = array[i] ?: return null
                Base(
                    entry[BASE_TYPE_IN_ENTRY]?.let { classAt(it.address) } ?: return null,
                    isVirtual = entry.flag(IS_VIRTUAL),
                    access = if (entry.flag(IS_PUBLIC)) Access.PUBLIC else Access.PRIVATE,
                )
            }
        }

        // The vptr is the vtable's address point, two words past its `_ZTV` label.
        private fun kindOf(zti: Address) =
            pointee(zti, Itanium.vtablePrefixBytes(ptr)) { it.vtableClass?.let(TypeinfoKind::ofVtableClass) }

        /** The class whose typeinfo the pointer at [at] points at. */
        private fun classAt(at: Address) = pointee(at, 0) { it.typeinfoClass }

        /**
         * [of] the first symbol the pointer at [at] refers to that it answers for: an external one by
         * Ghidra's reference to it, else a label at the address the pointer holds or [back] bytes before.
         */
        private fun <T : Any> pointee(at: Address, back: Long, of: (Symbol) -> T?): T? {
            val external = program.referenceManager.getReferencesFrom(at)
                .filter { it.isExternalReference || it.toAddress.isExternalAddress }
                .mapNotNull { symtab.getPrimarySymbol(it.toAddress) }
            val symbols = external.ifEmpty {
                val target = runCatching { program.readPointer(at) }.getOrNull() ?: return null
                val before = runCatching { target.subtract(back) }.getOrNull()?.takeIf { back > 0 }
                symtab.getSymbols(target).toList() + before?.let { symtab.getSymbols(it).toList() }.orEmpty()
            }
            return symbols.firstNotNullOfOrNull(of)
        }
    }
}
