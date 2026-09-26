package ghidra.program.model.gclass

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataTypePath

/** `ghidra.program.model.gclass` arrives in 11.4; the names and paths it publishes are long-standing. */
object ClassUtils {
    const val VFPTR = "vfptr"

    @JvmStatic
    fun getClassInternalsPath(path: CategoryPath, className: String) =
        CategoryPath(CategoryPath(path, className), "!internal")

    @JvmStatic
    fun getClassInternalsPath(composite: Composite) =
        composite.dataTypePath.let { getClassInternalsPath(it.categoryPath, it.dataTypeName) }

    @JvmStatic
    fun getBaseClassDataTypePath(composite: Composite) = DataTypePath(getClassInternalsPath(composite), composite.name)
}
