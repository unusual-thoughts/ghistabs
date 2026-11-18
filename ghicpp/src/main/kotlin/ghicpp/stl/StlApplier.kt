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

    private val index by lazy { StlIndex(archive) }

    fun apply(): Result {
        val (replaced, filled) = replacePlaceholders()
        val laid = layClasses()
        if (roots == GNU_ROOTS) nameAliasedClasses()
        return Result(replaced, filled, record(), laid)
    }

    /**
     * Files each class the GNU demangler names by an alias ([gnuAliases]) under that alias, in place of the
     * empty struct Ghidra made for its methods' `this`: a method of `std::__cxx11::string` takes a
     * `string *`, and Ghidra finds a class's struct by the class's own name, so the class must be the
     * struct `/std/__cxx11/string`. A function taking `std::string const&` then passes the same type its
     * methods take, where it took a `basic_string<char,…> *` the decompiler cast at every call. The
     * archive's typedef of the alias, if it came in, is folded into the class. Returns how many it named.
     */
    private fun nameAliasedClasses(): Int {
        var named = 0
        for (category in listOf(CategoryPath("/std"), CategoryPath("/std/__cxx11"))) {
            val structs = dtm.getCategory(category)?.dataTypes.orEmpty().filterIsInstance<Structure>()
                .filterNot { it.isNotYetDefined }
                .groupBy { StlIndex.key(category.pathElements.toList() + it.name) }
            for ((alias, target) in gnuAliases()) {
                val real = structs[StlIndex.key(category.pathElements.toList() + target)]?.singleOrNull() ?: continue
                val existing = dtm.getDataType(category, alias)
                val foldable = existing == null || (existing is Structure && existing.isNotYetDefined) ||
                    (existing is TypeDef && existing.baseDataType == real)
                if (!foldable) continue
                if (existing != null) dtm.replaceDataType(existing, real, false)
                if (runCatching { real.name = alias }.isSuccess) named++
            }
        }
        return named
    }

    private fun replacePlaceholders(): Pair<Int, Int> {
        val stubs = mutableListOf<Pair<Structure, Composite>>()
        dtm.allStructures.forEach { stub ->
            if (!stub.isNotYetDefined) return@forEach
            val path = archivePath(stub.categoryPath, roots) ?: return@forEach
            val layout = lookup(archive, path, stub.name, index) ?: return@forEach
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
        val layout = lookup(archive, CategoryPath(CategoryPath.ROOT, scopes), ns.name, index)
        val laid = layout != null && (dtm.getDataType(layout.dataTypePath) as? Composite)?.isNotYetDefined == false
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
            .groupBy { StlIndex.key(canonical(archive, it.getPathList(true))) }
            .mapValues { (_, group) -> group.firstOrNull { !it.isExternal } ?: group.first() }
        val old = program.readClassRecord().orEmpty()
        val name = archive.name.removeSuffix(".gdt")
        val entries = classes.mapNotNull { cls ->
            val ns: GhidraClass = namespaces[StlIndex.key(cls.segments)] ?: return@mapNotNull null
            if (ns.id in old) return@mapNotNull null
            val struct = dtm.getDataType(cls.path) as? Structure
            val bases = cls.bases.map { base ->
                val segments = StdClass(base.path).segments
                val baseNs = namespaces[StlIndex.key(segments)]
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

        /** libstdc++'s: `__gnu_cxx` holds its extensions and the iterators of its containers. */
        @JvmField
        val GNU_ROOTS = setOf("std", "__gnu_cxx")

        /**
         * The names Ghidra's GNU demangler (11.4 on) puts in place of a library template, with the class each
         * stands for, as the demangler and the DWARF importer spell it: `string` for
         * `basic_string<char,_std::char_traits<char>,_std::allocator<char>_>`. A GNU archive keeps each as a
         * typedef of the class, in `std` and in `std::__cxx11`, which [lookup] follows.
         */
        @JvmStatic
        fun gnuAliases(): Map<String, String> = buildMap {
            for ((prefix, char) in listOf("" to "char", "w" to "wchar_t")) {
                val traits = "std::char_traits<$char>"
                val alloc = "std::allocator<$char>"
                for (name in listOf(
                    "ios", "streambuf", "istream", "ostream", "iostream", "filebuf",
                    "ifstream", "ofstream", "fstream",
                )) {
                    put("$prefix$name", spelled("basic_$name<$char, $traits >"))
                }
                for (name in listOf("string", "stringbuf", "istringstream", "ostringstream", "stringstream")) {
                    put("$prefix$name", spelled("basic_$name<$char, $traits, $alloc >"))
                }
            }
            for (char in listOf("char8_t", "char16_t", "char32_t")) {
                put(
                    char.removeSuffix("_t").replace("char", "u") + "string",
                    spelled("basic_string<$char, std::char_traits<$char>, std::allocator<$char> >"),
                )
            }
        }

        private fun categoryOf(scopes: List<String>) =
            if (scopes.isEmpty()) CategoryPath.ROOT else CategoryPath(CategoryPath.ROOT, scopes)

        private fun spelled(cxx: String) = cxx.replace(' ', '_')

        /**
         * The class [archive] files at [category] / [name], through the typedefs it keeps for the names a
         * demangler gives a library template ([gnuAliases]), in the name or in any scope of the category;
         * failing that, the one [index] finds however the demangler spelled it. Null if it has none, or only
         * an empty one.
         */
        @JvmStatic
        @JvmOverloads
        fun lookup(
            archive: DataTypeManager,
            category: CategoryPath,
            name: String,
            index: StlIndex? = null,
        ): Composite? {
            val path = category.pathElements.toList() + name
            val scopes = canonical(archive, path)
            val found = archive.getDataType(DataTypePath(categoryOf(scopes.dropLast(1)), scopes.last()))
            return (found as? Composite)?.takeUnless { it.isNotYetDefined } ?: index?.find(path)
        }

        /** [path], each scope that names a typedef of [archive]'s replaced by the class it names. */
        fun canonical(archive: DataTypeManager, path: List<String>): List<String> {
            val out = mutableListOf<String>()
            for (segment in path) {
                val category = categoryOf(out)
                val typedef = archive.getDataType(category, segment) as? TypeDef
                val target = typedef?.baseDataType as? Composite
                out.add(if (target != null && target.categoryPath == category) target.name else segment)
            }
            return out
        }

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
