package ghicpp.stl

import generic.jar.ResourceFile
import ghicpp.Access
import ghicpp.ClassHierarchyRecords
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghidra.framework.Application
import ghidra.program.database.data.DataTypeManagerDB
import ghidra.program.database.data.replaceDataTypesBatched
import ghidra.program.model.data.*
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import java.io.File

/**
 * The MSVC runtime a program links: the version of the `MSVCP<nn>.DLL` it imports, and whether it is
 * the debug build, `MSVCP<nn>D.DLL`, whose iterator-debugging containers are laid out differently.
 */
data class MsvcRuntime(val version: Int, val debug: Boolean) {
    /** The bundled archive of this runtime's standard library for [pointerSize], if there is one. */
    fun archive(pointerSize: Int): String? {
        val arch = when (pointerSize) {
            4 -> "x86"
            8 -> "x64"
            else -> return null
        }
        return "msvcp$version${if (debug) "d" else ""}_$arch".takeIf { it in BUNDLED }
    }

    companion object {
        private val DLL = Regex("""MSVCP(\d+)(\w*)\.DLL""", RegexOption.IGNORE_CASE)

        /** What [MsvcStlArchives] ships: the archives CI builds (see tools/stl-archives). */
        val BUNDLED = setOf(
            "msvcp140_x86",
            "msvcp140_x64",
            "msvcp140d_x86",
            "msvcp140d_x64",
            "msvcp90_x86",
            "msvcp90_x64",
        )

        /**
         * The runtime among a program's imported [libraries]. msvcp140 comes with satellites
         * (`MSVCP140_1.DLL`, `MSVCP140_ATOMIC_WAIT.DLL`, debug `MSVCP140_1D.DLL`, `MSVCP140D_ATOMIC_WAIT.DLL`)
         * that say the same thing as the main DLL.
         */
        fun of(libraries: Iterable<String>): MsvcRuntime? = libraries.firstNotNullOfOrNull { name ->
            val match = DLL.matchEntire(name) ?: return@firstNotNullOfOrNull null
            val rest = match.groupValues[2].uppercase()
            val debug = rest == "D" || rest.startsWith("D_") || (rest.startsWith("_") && rest.endsWith("D"))
            MsvcRuntime(match.groupValues[1].toInt(), debug)
        }

        fun of(program: Program): MsvcRuntime? = of(program.externalManager.externalLibraryNames.asIterable())
    }
}

/**
 * The runtimes' archives, built on Ghidra 10.4 so every release ghicpp supports opens them (see
 * tools/stl-archives). They ship in the extension's `data/typeinfo/msvc`, where Ghidra lists them with its
 * own archives, so the types a program takes from one stay linked to it; a build that only has ghicpp's
 * jar (the ghistabs extension's tests, say) uses the copies in the jar.
 */
object MsvcStlArchives {
    fun open(name: String): FileDataTypeManager {
        require(name in MsvcRuntime.BUNDLED) { "no bundled archive $name" }
        val shipped = runCatching { Application.findDataFileInAnyModule("typeinfo/msvc/$name.gdt") }.getOrNull()
        val file = shipped?.takeIf { it.exists() } ?: ResourceFile(copyOut(name))
        return FileDataTypeManager.openFileArchive(file, false)
    }

    /** The bases of the classes in archive [name], off the PDB it was built from; empty when none ship. */
    fun classes(name: String): List<StdClass> {
        require(name in MsvcRuntime.BUNDLED) { "no bundled archive $name" }
        val shipped = runCatching { Application.findDataFileInAnyModule("typeinfo/msvc/$name.classes") }.getOrNull()
        val text = shipped?.takeIf { it.exists() }?.inputStream?.use { String(it.readBytes(), Charsets.UTF_8) }
            ?: MsvcStlArchives::class.java.getResourceAsStream("/ghicpp/stl/$name.classes")
                ?.use { String(it.readBytes(), Charsets.UTF_8) }
            ?: return emptyList()
        return StdClass.parse(text)
    }

    private val dir by lazy {
        File(System.getProperty("java.io.tmpdir"), "ghicpp-stl-${System.getProperty("user.name")}").apply { mkdirs() }
    }

    private fun copyOut(name: String): File {
        val bytes = checkNotNull(MsvcStlArchives::class.java.getResourceAsStream("/ghicpp/stl/$name.gdt")) {
            "missing resource $name.gdt"
        }.use { it.readBytes() }
        val file = File(dir, "$name.gdt")
        if (!file.isFile || !file.readBytes().contentEquals(bytes)) {
            val tmp = File.createTempFile(name, ".tmp", dir)
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(file)) {
                file.delete()
                check(tmp.renameTo(file)) { "cannot write $file" }
            }
        }
        return file
    }
}

/** A direct base of a [StdClass]: the base at its archive [path], and how the class holds it. */
data class StdBase(val path: String, val access: Access, val isVirtual: Boolean, val offset: Long?)

/**
 * A class as the runtime's PDB declares it, at its archive [path]: its direct [bases], which its struct alone
 * loses (an empty base takes no bytes, and nothing there says access or virtuality).
 */
data class StdClass(val path: String, val bases: List<StdBase>) {
    /** Its namespace path: `std`, `basic_streambuf<…>` for `/std/basic_streambuf<…>`. */
    val segments: List<String> get() = CategoryPath(path).pathElements.toList()

    companion object {
        /**
         * Reads the `.classes` text `MsvcStlArchiveScript` writes beside an archive (its header gives the
         * format): `C <path>`, then a tab-indented `B <access> <offset> <path>` per non-virtual base and
         * `V <access> <vbptr offset> <vbtable index> <path>` per virtual one.
         */
        fun parse(text: String): List<StdClass> {
            val classes = mutableListOf<Pair<String, MutableList<StdBase>>>()
            for (line in text.lineSequence().filter { it.isNotBlank() }) {
                val fields = line.trimStart('\t').split('\t')
                when {
                    !line.startsWith('\t') && fields[0] == "C" -> classes += fields[1] to mutableListOf()

                    fields[0] == "B" -> classes.last().second +=
                        StdBase(fields[3], access(fields[1]), isVirtual = false, offset = fields[2].toLong())

                    fields[0] == "V" -> classes.last().second +=
                        StdBase(fields[4], access(fields[1]), isVirtual = true, offset = null)
                }
            }
            return classes.map { (path, bases) -> StdClass(path, bases) }
        }

        private fun access(name: String) = Access.valueOf(name.uppercase())
    }
}

/**
 * Fills the program's empty `std` structs from the runtime's [archive]. Ghidra's Microsoft demangler
 * makes an empty placeholder for each class a demangled method belongs to, at the class's namespace path
 * under `/Demangler`, and the archive files each type at that same path without it. Only the types
 * standing in for a placeholder, and those of the std classes the program has a class namespace for (its
 * RTTI's), are resolved, with what they depend on, and they stay linked to the archive they came from. So
 * a placeholder `/Demangler/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>` is replaced, at every
 * use, by the runtime's `/std/basic_string<…>`, and an empty one already at `/std/…` is filled in place.
 *
 * Runs in the caller's transaction.
 */
class MsvcStlApplier(
    private val program: Program,
    private val archive: DataTypeManager,
    private val classes: List<StdClass> = emptyList(),
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
            val path = archivePath(stub.categoryPath) ?: return@forEach
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
        if (scopes.firstOrNull() !in ROOTS) return@count false
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
                val segments = StdClass(base.path, emptyList()).segments
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
        private val ROOTS = setOf("std", "stdext")

        /** Where the archive files the type a placeholder at [category] stands for; null outside std. */
        fun archivePath(category: CategoryPath): CategoryPath? {
            val names = category.pathElements.toList()
                .let { if (it.firstOrNull() == "Demangler") it.drop(1) else it }
            if (names.firstOrNull() !in ROOTS) return null
            return CategoryPath(CategoryPath.ROOT, names)
        }
    }
}
