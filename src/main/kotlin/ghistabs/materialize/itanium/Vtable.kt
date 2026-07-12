package ghistabs.materialize.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.LongDataType
import ghidra.program.model.data.LongLongDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.PointerTypedef
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.UnsignedIntegerDataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.harvest.TypeResolver
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.MethodDecl
import ghistabs.parse.TypeDecl
import ghistabs.parse.VirtKind

/**
 * Collects a class's full vtable slot list from its inheritance chain and orders it by the
 * stab-declared slot offset. The walk gathers virtuals bases-first so a derived override (matched
 * by name) replaces the inherited slot and its offset wins; output order is set by the final sort,
 * not the walk. Override matching is by name only — fine for the non-overloaded gcc 3.4.4 corpus.
 */
class Virtuals(
    private val typeResolver: TypeResolver,
    private val table: MutableList<MethodDecl<GlobalTypeId>> = mutableListOf(),
    private val visited: MutableSet<TypeDecl.Struct<GlobalTypeId>> = mutableSetOf(),
) {
    private fun walkBases(cls: TypeDecl.Struct<GlobalTypeId>) {
        for (base in cls.bases) {
            typeResolver.resolveBaseAstStatic(base.type)?.takeIf { visited.add(it) }?.let { collectAll(it) }
        }
    }

    private fun collectAll(cls: TypeDecl.Struct<GlobalTypeId>) {
        walkBases(cls)
        for (m in cls.methods.filter { it.virt == VirtKind.VIRTUAL }) {
            val idx = table.indexOfFirst { it.name == m.name }
            if (idx >= 0) table[idx] = m else table += m
        }
    }

    fun process(cls: TypeDecl.Struct<GlobalTypeId>): List<MethodDecl<GlobalTypeId>> {
        collectAll(cls)
        return table.sortedBy { it.vtableOffsetBits!! }
    }
}

/**
 * Lay the Itanium vtable at [ztv] and return its address point. The `offset_to_top` + `rtti`
 * header words go at [ztv] (which `_ZTV<class>` already labels); the [vftable] function-pointer
 * array + a "vftable" symbol go at the address point (`ztv + 2*ptrSize`) — the value a `{vfptr}`
 * holds — so a constructor's `this->vfptr = &<Class>::vftable` resolves to a symbol, not a raw
 * address. The rtti pointee stays an untyped `void*` until backlog §24 wires it.
 */
fun Program.layVtable(ztv: Address, vftable: Structure, className: String, ns: Namespace): Address {
    val addressPoint = ztv.add(Itanium.vtablePrefixBytes(defaultPointerSize))

    listing.clearCodeUnits(ztv, addressPoint.add(vftable.length.toLong() - 1), false)
    listing.createData(ztv, Itanium.offsetToTopType(defaultPointerSize))
    listing.setComment(ztv, CommentType.EOL, "${Itanium.OFFSET_TO_TOP} (to top of complete object)")
    val rttiAddr = ztv.add(defaultPointerSize.toLong())
    listing.createData(rttiAddr, PointerDataType(dataTypeManager))
    listing.setComment(rttiAddr, CommentType.EOL, "${Itanium.RTTI}: ${Itanium.zti(className)} typeinfo")
    listing.createData(addressPoint, vftable)
    symbolTable.createLabel(addressPoint, Itanium.VFTABLE, ns, SourceType.IMPORTED)
    return addressPoint
}

/**
 * Authoritative Itanium `__cxxabiv1` typeinfo struct layouts, adapted from Ghidra's
 * `RTTIGccClassRecoverer`. The implementation of last resort for the gcc-internal
 * `__*_type_info_pseudo` records that are absent from the stabs on xapasmcsr etc:
 * [pseudoTypeInfo] maps a stab pseudo-type name to the reference layout. Pointer size and
 * endianness come from the [dtm]'s data organization, so no `Program` is needed.
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

    val classTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "ClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, PointerDataType.dataType, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            setPackingEnabled(true)
        }
    }

    val siClassTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "SiClassTypeInfoStructure", 0, dtm).apply {
            add(PointerTypedef(null, null, -1, dtm, componentOffset), "classTypeinfoPtr", null)
            add(dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(dtm.getPointer(classTypeInfoStructure), "baseClassTypeInfoPtr", null)
            setPackingEnabled(true)
        }
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

            setPackingEnabled(true)
        }
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
            setPackingEnabled(true)
        }
}
