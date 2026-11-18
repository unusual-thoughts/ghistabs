package ghicpp.stl

import ghicpp.ClassNaming
import ghicpp.copyNonVirtualPart
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils

/**
 * Lays each base subobject of a standard library archive's classes whose class has virtual bases as that
 * class's non-virtual part alone, its self-base, filed where Ghidra's PDB importer files one
 * ([ClassUtils.getBaseClassDataTypePath]), as ghicpp's class passes lay a program's: debug info that sizes
 * such a class whole, its virtual bases counted, leaves no room for it as a base, so the importer drops it
 * (`basic_iostream` in `basic_stringstream`) or overlaps what follows it with its virtual bases.
 *
 * A self-base runs to the end of the class's last non-virtual member, a base's own self-base counted for a
 * base, rounded up to [pointerSize]: the vptr every class with virtual bases holds.
 */
object StlSelfBases {
    @JvmStatic
    fun apply(dtm: DataTypeManager, classes: List<StdClass>, pointerSize: Int): Int {
        val shapes = Shapes(dtm, classes, pointerSize)
        var laid = 0
        for (cls in StlShape.baseFirst(classes)) {
            val struct = dtm.getDataType(cls.path) as? Structure ?: continue
            val direct = cls.bases.filterNot { it.isVirtual }
            laid += direct.count { shapes.laySelfBase(struct, it, direct.size) }
        }
        return laid
    }

    /** Whether [type] is the class at [path] or its self-base. */
    private fun isOf(type: String, path: String) = type == path || type.startsWith("$path/")

    /** What the classes' non-virtual parts are, off their structs as laid so far. */
    private class Shapes(val dtm: DataTypeManager, classes: List<StdClass>, val pointerSize: Int) {
        private val byPath = classes.associateBy { it.path }
        private val virtual = mutableMapOf<String, Boolean>()
        private val sizes = mutableMapOf<String, Int>()

        fun hasVirtualBases(path: String, seen: Set<String> = emptySet()): Boolean = virtual.getOrPut(path) {
            val cls = byPath[path] ?: return@getOrPut false
            path !in seen && cls.bases.any { it.isVirtual || hasVirtualBases(it.path, seen + path) }
        }

        fun nonVirtualSize(path: String): Int? {
            sizes[path]?.let { return it }
            val struct = dtm.getDataType(path) as? Structure ?: return null
            val bases = byPath[path]?.bases.orEmpty().filterNot { it.isVirtual }
            val end = struct.definedComponents.maxOfOrNull { c ->
                val base = bases.firstOrNull { it.offset?.toInt() == c.offset && isOf(c.dataType.pathName, it.path) }
                c.offset + (base?.takeIf { hasVirtualBases(it.path) }?.let { nonVirtualSize(it.path) } ?: c.length)
            } ?: 0
            return ((end + pointerSize - 1) / pointerSize * pointerSize).also { sizes[path] = it }
        }

        /** Lays [base] of [struct], one of [bases] direct ones, as its self-base, if it has virtual bases. */
        fun laySelfBase(struct: Structure, base: StdBase, bases: Int): Boolean {
            val at = base.offset?.toInt() ?: return false
            if (!hasVirtualBases(base.path)) return false
            val whole = dtm.getDataType(base.path) as? Structure ?: return false
            val size = nonVirtualSize(base.path)?.takeIf { it in 1..<whole.length } ?: return false
            val self = selfBase(dtm, whole, size)
            for (c in struct.definedComponents.reversed()) {
                if (c.offset < at + size && c.offset + c.length > at) struct.clearAtOffset(c.offset)
            }
            if (at + size > struct.length) return false
            val name = ClassNaming.baseFieldName(false, CategoryPath(base.path).name, bases)
            return runCatching { struct.replaceAtOffset(at, self, size, name, null) }.isSuccess
        }
    }

    private fun selfBase(dtm: DataTypeManager, cls: Structure, size: Int): Structure {
        val path = ClassUtils.getBaseClassDataTypePath(cls)
        (dtm.getDataType(path) as? Structure)?.takeIf { it.length == size }?.let { return it }
        val self = StructureDataType(path.categoryPath, path.dataTypeName, size, dtm)
        self.description = "${cls.name} as a base subobject"
        self.copyNonVirtualPart(cls)
        return dtm.resolve(self, DataTypeConflictHandler.REPLACE_HANDLER) as Structure
    }
}
