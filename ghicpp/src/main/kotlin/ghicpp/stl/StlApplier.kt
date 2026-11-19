package ghicpp.stl

import ghicpp.ClassHierarchyRecords
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghidra.program.database.data.DataTypeManagerDB
import ghidra.program.database.data.replaceDataTypesBatched
import ghidra.program.model.data.*
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program

/**
 * Fills the program's empty standard library structs from its runtime's [archive], whichever ABI's.
 * Ghidra's demanglers make an empty placeholder for each class a demangled method belongs to, at the
 * class's namespace path under `/Demangler`, and the archive files each type at that same path without
 * it; [roots] are the library's top namespaces. Only the types
 * standing in for a placeholder, and those of the std classes the program has a class namespace for (its
 * RTTI's), are resolved, with what they depend on, and they stay linked to the archive they came from. So
 * a placeholder `/Demangler/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>` is replaced, at every
 * use, by the runtime's `/std/basic_string<…>`, and an empty one already at `/std/…` is filled in place.
 *
 * Runs in the caller's transaction.
 */
class StlApplier(
    private val program: Program,
    private val archive: DataTypeManager,
    private val classes: List<StdClass> = emptyList(),
    private val roots: Set<String> = MSVC_ROOTS,
) {
    /**
     * How many placeholders it [replaced] and [filled] in place, how many class namespaces' types it [laid]
     * with no placeholder for them, and how many classes' bases it [recorded].
     */
    data class Result(val replaced: Int, val filled: Int, val recorded: Int = 0, val laid: Int = 0)

    private val dtm = program.dataTypeManager

    fun apply(): Result {
        val (replaced, filled) = replacePlaceholders()
        val laid = layClasses()
        return Result(replaced, filled, record(), laid)
    }

    private fun replacePlaceholders(): Pair<Int, Int> {
        val stubs = mutableListOf<Pair<Structure, Composite>>()
        dtm.allStructures.forEach { stub ->
            if (!stub.isNotYetDefined) return@forEach
            val path = archivePath(stub.categoryPath, roots) ?: return@forEach
            val layout = archive.getDataType(DataTypePath(path, stub.name)) as? Composite ?: return@forEach
            if (!layout.isNotYetDefined) stubs.add(stub to layout)
        }
        if (stubs.isEmpty()) return 0 to 0

        // An empty struct already at the archive's path is filled in place by the conflict handler; a
        // placeholder under /Demangler is swapped for the resolved type everywhere it is used.
        val resolved = stubs.map { (stub, layout) ->
            stub to dtm.resolve(layout, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
        }
        val replacements = resolved.filter { (stub, type) -> stub !== type && dtm.contains(stub) }
            .map { (stub, type) -> stub as DataType to type }
        (dtm as DataTypeManagerDB).replaceDataTypesBatched(replacements)
        return replacements.size to stubs.size - replacements.size
    }

    /**
     * Resolves the archive's type for each std class namespace the program has, its RTTI's say, that no
     * placeholder brought in: the struct the class passes take for it ([ghicpp.knownLayout]) rather than
     * build their own. Returns how many it resolved.
     */
    private fun layClasses(): Int = program.symbolTable.classNamespaces.asSequence().count { ns ->
        val scopes = ns.getPathList(true).dropLast(1)
        if (scopes.firstOrNull() !in roots) return@count false
        val path = DataTypePath(CategoryPath(CategoryPath.ROOT, scopes), ns.name)
        val layout = archive.getDataType(path) as? Composite
        val laid = (dtm.getDataType(path) as? Composite)?.isNotYetDefined == false
        if (layout == null || layout.isNotYetDefined || laid) return@count false
        dtm.resolve(layout, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
        true
    }

    /**
     * Records the bases of each of [classes] the program has a class namespace for, where nothing recorded
     * that class yet: an imported class's namespace, under its library, where the program defines none of
     * its own. A base with no namespace goes by its qualified name. Returns how many it recorded.
     */
    private fun record(): Int {
        if (classes.isEmpty()) return 0
        val namespaces = program.symbolTable.classNamespaces.asSequence().toList()
            .groupBy { it.getPathList(true) }
            .mapValues { (_, group) -> group.firstOrNull { !it.isExternal } ?: group.first() }
        val old = program.readClassRecord().orEmpty()
        val name = archive.name.removeSuffix(".gdt")
        val entries = classes.mapNotNull { cls ->
            val ns: GhidraClass = namespaces[cls.segments] ?: return@mapNotNull null
            if (ns.id in old) return@mapNotNull null
            val struct = dtm.getDataType(cls.path) as? Structure
            val bases = cls.bases.map { base ->
                val segments = StdClass(base.path).segments
                val baseNs = namespaces[segments]
                ClassHierarchyRecords.Base(
                    baseNs?.id,
                    if (baseNs == null) segments.joinToString("::") else null,
                    base.isVirtual,
                    base.access,
                    base.offset,
                )
            }
            ns.id to ClassHierarchyRecords.Entry(struct?.let(dtm::getID)?.takeIf { it >= 0 }, bases, name)
        }
        if (entries.isNotEmpty()) program.writeClassRecord(old + entries)
        return entries.size
    }

    companion object {
        /** MSVC's standard library namespaces. */
        val MSVC_ROOTS = setOf("std", "stdext")

        /**
         * Where the archive files the type a placeholder at [category] stands for; null outside the
         * library's [roots].
         */
        fun archivePath(category: CategoryPath, roots: Set<String> = MSVC_ROOTS): CategoryPath? {
            val names = category.pathElements.toList()
                .let { if (it.firstOrNull() == "Demangler") it.drop(1) else it }
            if (names.firstOrNull() !in roots) return null
            return CategoryPath(CategoryPath.ROOT, names)
        }
    }
}
