package ghistabs.materialize.itanium

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
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.data.UnsignedIntegerDataType
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
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
 * Populate the two Itanium vtable structs (both cleared first, so re-entrant):
 *   [vftable] — the function-pointer array; one slot per virtual, `name` → resolved pointer type.
 *   [vtable]  — the `_ZTV` record: `offset_to_top` + `rtti` + the embedded [vftable].
 */
fun buildVtableRecord(
    vtable: Structure,
    vftable: Structure,
    slots: List<Pair<String, DataType>>,
    className: String,
    ptrSize: Int,
    dtm: DataTypeManager,
) {
    while (vftable.numComponents > 0) vftable.delete(0)
    for ((name, slotType) in slots) vftable.add(slotType, ptrSize, name, "virtual $name")

    while (vtable.numComponents > 0) vtable.delete(0)
    vtable.add(Itanium.offsetToTopType(ptrSize), ptrSize, Itanium.OFFSET_TO_TOP, "offset to top of complete object")
    vtable.add(
        PointerDataType.getPointer(Undefined4DataType.dataType, dtm),
        ptrSize,
        Itanium.RTTI,
        "${Itanium.zti(className)} typeinfo pointer",
    )
    vtable.add(vftable, vftable.length, Itanium.VFTABLE, "virtual function table")
}

/**
 * Authoritative Itanium `__cxxabiv1` typeinfo struct layouts, adapted from Ghidra's
 * `RTTIGccClassRecoverer`. Intended as the implementation of last resort for the gcc-internal
 * `__class_type_info`(-pseudo) records that are absent from the stabs on xapasmcsr etc.
 */
class RttiStructs(val ctx: ImportContext<*>) {
    val program = ctx.program

    private val componentOffset = Itanium.vtablePrefixBytes(program.defaultPointerSize).toLong()

    val classTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "ClassTypeInfoStructure", 0, ctx.dtm).apply {
            add(
                PointerTypedef(null, PointerDataType.dataType, -1, ctx.dtm, componentOffset),
                "classTypeinfoPtr",
                null,
            )
            add(dataTypeManager.getPointer(CharDataType()), "typeinfoName", null)
            setPackingEnabled(true)
        }
    }

    val siClassTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "SiClassTypeInfoStructure", 0, ctx.dtm).apply {
            add(PointerTypedef(null, null, -1, ctx.dtm, componentOffset), "classTypeinfoPtr", null)
            add(ctx.dtm.getPointer(CharDataType()), "typeinfoName", null)
            add(ctx.dtm.getPointer(classTypeInfoStructure), "baseClassTypeInfoPtr", null)
            setPackingEnabled(true)
        }
    }

    val baseClassTypeInfoStructure by lazy {
        StructureDataType(Itanium.classDataTypesRoot, "BaseClassTypeInfoStructure", 0, ctx.dtm).apply {
            add(ctx.dtm.getPointer(classTypeInfoStructure), "classTypeinfoPtr", null)

            val (offsetBitSize, dataType) = when (program.defaultPointerSize) {
                8 -> 56 to LongLongDataType()
                else -> 24 to LongDataType()
            }

            if (program.memory.isBigEndian) {
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
        StructureDataType(Itanium.classDataTypesRoot, "VmiClassTypeInfoStructure$numBaseClasses", 0, ctx.dtm).apply {
            add(PointerTypedef(null, null, -1, ctx.dtm, componentOffset), "classTypeinfoPtr", null)
            add(dataTypeManager.getPointer(CharDataType()), "typeinfoName", null)
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
