package ghicpp.stl

import ghidra.program.model.data.Array
import ghidra.program.model.data.Category
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.TypeDef
import ghidra.util.task.TaskMonitor

/** What the archive scripts share, whichever ABI's debug info they build from. */
object StlArchiveTypes {
    /**
     * Drops every type of [dtm] that no type filed under one of the library's [roots] reaches, then the
     * categories left empty. Returns how many types it dropped.
     */
    @JvmStatic
    fun prune(dtm: DataTypeManager, roots: Set<String>, monitor: TaskMonitor): Int {
        val types = mutableListOf<DataType>().also { dtm.getAllDataTypes(it) }
        val keep = mutableSetOf<DataType>()
        val work = ArrayDeque(
            types.filter {
                it !is FunctionDefinition && !it.categoryPath.isRoot && it.categoryPath.pathElements[0] in roots
            },
        )
        while (work.isNotEmpty()) {
            val dt = work.removeFirst()
            if (keep.add(dt)) work.addAll(dependencies(dt))
        }
        val drop = types.filterNot { it in keep }
        dtm.remove(drop, monitor)
        removeEmptyCategories(dtm.rootCategory, monitor)
        return drop.size
    }

    /** Removes [category]'s subcategories that hold no type, at any depth. */
    @JvmStatic
    fun removeEmptyCategories(category: Category, monitor: TaskMonitor) {
        for (sub in category.categories) {
            removeEmptyCategories(sub, monitor)
            if (sub.dataTypes.isEmpty() && sub.categories.isEmpty()) category.removeEmptyCategory(sub.name, monitor)
        }
    }

    private fun dependencies(dt: DataType): List<DataType> = when (dt) {
        is Composite -> dt.definedComponents.map { it.dataType }
        is Pointer -> listOfNotNull(dt.dataType)
        is Array -> listOf(dt.dataType)
        is TypeDef -> listOf(dt.dataType)
        is FunctionDefinition -> listOf(dt.returnType) + dt.arguments.map { it.dataType }
        else -> emptyList()
    }
}
