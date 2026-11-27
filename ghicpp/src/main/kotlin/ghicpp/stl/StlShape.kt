package ghicpp.stl

import ghicpp.BaseSplitter
import ghicpp.ClassNaming
import ghicpp.vfptrOffset
import ghicpp.vptrInBase
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils
import ghidrakt.DtmRegistry
import ghidrakt.diagnose.DummySink

/**
 * Gives a standard library archive's classes the shape ghicpp's class passes give a program's
 * ([ghicpp.VfptrModel.SPLIT_BASE]), whichever ABI's: the names ghicpp reads a class by, and a vftable of
 * its own for every class that introduces virtual functions.
 *
 * 1. Each base subobject the debug info laid is named as ghicpp names one (`_base_`, `_base_<Base>` beside
 *    others) and each vptr `vfptr`, so the class passes see the bases and the vptr in a runtime's layout.
 * 2. A class holding its own vptr gets its `<Class>_vftable` ([StlVftables.lay]).
 * 3. A class sharing its primary base's vptr that introduces slots gets a `<Class>_vftable` too, the base's
 *    slots and then its own, and takes the vptr over: the base goes in as its fields around it, as
 *    [BaseSplitter] splits a program's class. Bases come first, so a base is split before its deriving
 *    classes copy its table.
 */
object StlShape {
    /** What [apply] did: bases named, own vftables laid, classes split around a vftable of their own. */
    data class Result(val bases: Int, val vftables: Int, val split: Int)

    @JvmStatic
    fun apply(
        dtm: DataTypeManager,
        classes: List<StdClass>,
        pointerSize: Int,
        typeOf: (StdClass, StdSlot) -> DataType?,
    ): Result {
        val bases = classes.sumOf { nameBases(dtm, it) }
        nameVfptrs(dtm)
        val vftables = StlVftables.lay(dtm, classes, pointerSize, typeOf)
        val splitter = BaseSplitter(DtmRegistry(dtm), DummySink, pointerSize)
        val split = baseFirst(classes).count { split(dtm, splitter, it, pointerSize, typeOf) }
        dropEmptyRuns(dtm)
        return Result(bases, vftables, split)
    }

    /**
     * Takes out the empty runs a split leaves where a base is nothing but its vptr ([BaseSplitter.splitBase]'s
     * zero-length `_base_`), and the components holding them. A Ghidra before 11 cannot hold an empty struct
     * in a component without it taking a byte, so an archive keeping them reads back a byte longer there.
     */
    private fun dropEmptyRuns(dtm: DataTypeManager) {
        val empty = mutableMapOf<Structure, Boolean>()

        // A split's own runs only: an empty class of the library's (a lambda) keeps its byte.
        fun Structure.isEmpty(): Boolean = empty.getOrPut(this) {
            empty[this] = false
            ClassNaming.FIELDS in name && isZeroLength &&
                definedComponents.all { (it.dataType as? Structure)?.isEmpty() == true }
        }
        val runs = dtm.allStructures.asSequence().filter { it.isEmpty() }.toList()
        dtm.allStructures.asSequence().filterNot { it in runs }.forEach { struct ->
            struct.definedComponents.filter { it.length == 0 && it.dataType in runs }
                .sortedByDescending { it.ordinal }
                .forEach { struct.delete(it.ordinal) }
        }
        runs.forEach { dtm.remove(it) }
    }

    /** Names [cls]'s non-virtual base subobjects, found at their offsets. Returns how many. */
    private fun nameBases(dtm: DataTypeManager, cls: StdClass): Int {
        val struct = dtm.getDataType(cls.path) as? Structure ?: return 0
        val direct = cls.bases.filterNot { it.isVirtual }
        return direct.count { base ->
            val at = base.offset?.toInt() ?: return@count false
            val comp = struct.definedComponents.firstOrNull { it.offset == at && it.dataType.pathName == base.path }
                ?: return@count false
            comp.fieldName = ClassNaming.baseFieldName(false, CategoryPath(base.path).name, direct.size)
            true
        }
    }

    /** The vptrs the debug info named its own way (`{vfptr}`), as ghicpp and Ghidra's class tools name them. */
    private fun nameVfptrs(dtm: DataTypeManager) {
        dtm.allStructures.forEach { struct ->
            struct.definedComponents.filter { it.fieldName == "{${ClassUtils.VFPTR}}" }
                .forEach { it.fieldName = ClassUtils.VFPTR }
        }
    }

    /** [classes], each after the ones it derives from. */
    internal fun baseFirst(classes: List<StdClass>): List<StdClass> {
        val byPath = classes.associateBy { it.path }
        val done = linkedMapOf<String, StdClass>()
        fun visit(cls: StdClass, seen: Set<String>) {
            if (cls.path in done || cls.path in seen) return
            cls.bases.mapNotNull { byPath[it.path] }.forEach { visit(it, seen + cls.path) }
            done[cls.path] = cls
        }
        classes.forEach { visit(it, emptySet()) }
        return done.values.toList()
    }

    private fun split(
        dtm: DataTypeManager,
        splitter: BaseSplitter,
        cls: StdClass,
        pointerSize: Int,
        typeOf: (StdClass, StdSlot) -> DataType?,
    ): Boolean {
        if (cls.slots.isEmpty()) return false
        val struct = dtm.getDataType(cls.path) as? Structure ?: return false
        if (struct.definedComponents.any { it.fieldName == ClassUtils.VFPTR }) return false
        // The primary base: the first one laid that holds a vptr.
        val (holder, inBase) = struct.definedComponents.filter { ClassNaming.isBaseField(it.fieldName.orEmpty()) }
            .firstNotNullOfOrNull { c -> (c.dataType as? Structure)?.vfptrOffset()?.let { c to it } }
            ?: return false
        val baseTable = tableAt(holder.dataType as Structure, inBase)
        val table = StructureDataType(CategoryPath(cls.path), struct.name + StlVftables.SUFFIX, 0, dtm)
        baseTable?.definedComponents?.forEach { table.lay(it.offset, it.dataType, it.fieldName) }
        StlVftables.slotNames(cls.slots).forEach { (slot, name) ->
            val target = typeOf(cls, slot)?.let { dtm.resolve(it, DataTypeConflictHandler.DEFAULT_HANDLER) }
            table.lay(slot.offset.toInt(), PointerDataType(target, pointerSize, dtm), name)
        }
        val laid = dtm.resolve(table, DataTypeConflictHandler.REPLACE_HANDLER)
        val vptr = holder.offset + vptrInBase(holder.dataType as Structure, inBase)
        return splitter.splitBase(struct, cls.segments, vptr, holder, PointerDataType(laid, pointerSize, dtm))
    }

    /** The vftable the vptr [at] bytes into [struct] points at, its own or a base subobject's. */
    private fun tableAt(struct: Structure, at: Int): Structure? {
        val comp = struct.getComponentContaining(at) ?: return null
        if (comp.fieldName == ClassUtils.VFPTR) return ((comp.dataType as? Pointer)?.dataType as? Structure)
        return (comp.dataType as? Structure)?.let { tableAt(it, at - comp.offset) }
    }

    private fun StructureDataType.lay(at: Int, dt: DataType, name: String?) {
        // An empty struct reports a length of 1, but grows from 0.
        val current = if (numComponents == 0 && isNotYetDefined) 0 else length
        if (at + dt.length > current) growStructure(at + dt.length - current)
        replaceAtOffset(at, dt, dt.length, name, null)
    }
}
