package ghicpp.stl

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils

/**
 * The vftables of a standard library archive's classes, whichever ABI's: for each class whose struct holds
 * its own `{vfptr}` and that introduces virtual functions ([StdClass.slots]), a `<Class>_vftable` struct of
 * a pointer per slot, filed in the class's own category, and its `{vfptr}` typed to point at it. A call
 * through the class (`_Ref_count_base::_Destroy`, `basic_streambuf::overflow`) then shows the slot by
 * name wherever the program has only the class, not a deriving one with a vftable of its own.
 */
object StlVftables {
    const val SUFFIX = "_vftable"

    /** Ghidra's class tools name a vfptr `vfptr`, its PDB applicator `{vfptr}`. */
    private val VFPTR_NAMES = setOf(ClassUtils.VFPTR, "{${ClassUtils.VFPTR}}")

    /**
     * Lays [classes]' vftables in [dtm], each slot a pointer to [typeOf] it where known, else to nothing,
     * pointers [pointerSize] bytes. Returns how many it laid.
     */
    @JvmStatic
    fun lay(
        dtm: DataTypeManager,
        classes: List<StdClass>,
        pointerSize: Int,
        typeOf: (StdClass, StdSlot) -> DataType?,
    ): Int = classes.count { cls ->
        val struct = dtm.getDataType(cls.path) as? Structure ?: return@count false
        val vfptr = struct.definedComponents.firstOrNull { it.fieldName in VFPTR_NAMES }
        if (cls.slots.isEmpty() || vfptr == null) return@count false
        val length = cls.slots.maxOf { it.offset }.toInt() + pointerSize
        val table = StructureDataType(CategoryPath(cls.path), struct.name + SUFFIX, length, dtm)
        for ((slot, name) in slotNames(cls.slots)) {
            val target = typeOf(cls, slot)?.let { dtm.resolve(it, DataTypeConflictHandler.DEFAULT_HANDLER) }
            val pointer = PointerDataType(target, pointerSize, dtm)
            table.replaceAtOffset(slot.offset.toInt(), pointer, pointerSize, name, null)
        }
        val laid = dtm.resolve(table, DataTypeConflictHandler.REPLACE_HANDLER)
        struct.replaceAtOffset(
            vfptr.offset,
            PointerDataType(laid, pointerSize, dtm),
            pointerSize,
            vfptr.fieldName,
            vfptr.comment,
        )
        true
    }

    /** [slots] in vftable order, each with its field name: overloads share one, the later taking a count after it. */
    fun slotNames(slots: List<StdSlot>): List<Pair<StdSlot, String>> {
        val names = mutableMapOf<String, Int>()
        return slots.sortedBy { it.offset }.map { slot ->
            val seen = names.merge(slot.name, 1, Int::plus)!!
            slot to if (seen == 1) slot.name else "${slot.name}_${seen - 1}"
        }
    }

    /** The vftable a `{vfptr}` [pointer] points at, if [StlVftables] laid one. */
    fun tableOf(pointer: DataType): Structure? =
        ((pointer as? Pointer)?.dataType as? Structure)?.takeIf { it.name.endsWith(SUFFIX) }
}
