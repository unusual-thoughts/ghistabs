package ghicpp.stl

import ghidra.program.database.data.DataTypeManagerDB
import ghidra.program.database.data.replaceDataTypesBatched
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program

/**
 * The MSVC runtime a program links: the version of the `MSVCP<nn>.DLL` it imports, and whether it is
 * the debug build, `MSVCP<nn>D.DLL`, whose iterator-debugging containers are laid out differently.
 */
data class MsvcRuntime(val version: Int, val debug: Boolean) {
    /** The bundled layouts of this runtime's standard library for [pointerSize], if there are any. */
    fun layouts(pointerSize: Int): String? {
        val arch = when (pointerSize) {
            4 -> "x86"
            8 -> "x64"
            else -> return null
        }
        return "msvcp$version${if (debug) "d" else ""}_$arch".takeIf { it in BUNDLED }
    }

    companion object {
        private val DLL = Regex("""MSVCP(\d+)(\w*)\.DLL""", RegexOption.IGNORE_CASE)

        /** What [StlLayouts] ships: the layouts CI builds (see tools/stl-archives). */
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
 * A runtime's standard library types, read from the text tools/stl-archives/ExportStlLayouts.java writes
 * out of the .gdt archive CI builds: Ghidra releases cannot open an archive a newer Ghidra wrote, and
 * ghicpp supports 10.4 on. The types are built unattached to any data type manager, sized as the PDB
 * laid them out, for [MsvcStlApplier] to resolve into a program.
 */
class StlLayouts private constructor(private val records: Map<String, Record>) {
    private class Record(val kind: Char, val fields: List<String>, val members: List<List<String>>)

    private val built = mutableMapOf<String, DataType>()
    private val filled = mutableSetOf<String>()

    operator fun get(path: DataTypePath): DataType? = records[path.path]?.let { type(path.path) }

    /** Every type, built: for checking a layout file whole. */
    fun all(): List<DataType> = records.keys.map { type(it) }

    private fun type(path: String): DataType {
        built[path]?.let { return it.also { fill(path, it) } }
        val record = records[path] ?: return builtin(path)
        val at = CategoryPath(path)
        val made: DataType = when (record.kind) {
            'S' -> StructureDataType(at.parent, at.name, record.fields[1].toInt())

            'U' -> UnionDataType(at.parent, at.name)

            'E' -> EnumDataType(at.parent, at.name, record.fields[1].toInt()).apply {
                record.members.forEach { (name, value) -> add(name, value.toLong()) }
            }

            'T' -> TypedefDataType(at.parent, at.name, ref(record.fields[1]))

            'F' -> FunctionDefinitionDataType(at.parent, at.name).also { built[path] = it }.apply {
                returnType = ref(record.fields[1])
                setVarArgs(record.fields[2] == "1")
                setArguments(
                    *record.members.map { (name, type) ->
                        ParameterDefinitionImpl(name.ifEmpty { null }, ref(type), null)
                    }.toTypedArray(),
                )
            }

            else -> error("unknown record ${record.kind} for $path")
        }
        built[path] = made
        fill(path, made)
        return made
    }

    /** A composite's members, once; first those it holds by value, which must have their size. */
    private fun fill(path: String, dt: DataType) {
        if (dt !is Composite || !filled.add(path)) return
        val record = records.getValue(path)
        for (member in record.members) {
            val bits = if (dt is Structure) member.size == 6 else member.size == 5
            val type = ref(if (dt is Structure) member[3] else member[2])
            when (dt) {
                is Structure -> {
                    val offset = member[0].toInt()
                    val length = member[1].toInt()
                    val name = member[2].ifEmpty { null }
                    if (bits) {
                        dt.insertBitFieldAt(offset, length, member[4].toInt(), type, member[5].toInt(), name, null)
                    } else if (length > 0) {
                        dt.replaceAtOffset(offset, type, length, name, null)
                    }
                }

                is Union -> {
                    val name = member[1].ifEmpty { null }
                    if (bits) {
                        dt.addBitField(type, member[4].toInt(), name, null)
                    } else {
                        dt.add(type, member[0].toInt(), name, null)
                    }
                }
            }
        }
    }

    /** A member's type: a path, then `|*<size>` for each pointer and `|[<count>]` for each array. */
    private fun ref(spec: String): DataType {
        val parts = spec.split('|')
        var dt: DataType? = if (parts[0] == "?") null else type(parts[0])
        for (wrap in parts.drop(1)) {
            dt = when {
                wrap.startsWith("*") -> PointerDataType(dt, wrap.drop(1).toInt())

                wrap.startsWith("[") -> {
                    val element = checkNotNull(dt) { "array of nothing in $spec" }
                    ArrayDataType(element, wrap.drop(1).dropLast(1).toInt(), element.length)
                }

                else -> error("bad type $spec")
            }
        }
        return checkNotNull(dt) { "nothing for $spec" }
    }

    companion object {
        private val BUILTINS: Map<String, DataType> = listOf(
            BooleanDataType.dataType, CharDataType.dataType, SignedCharDataType.dataType,
            UnsignedCharDataType.dataType, ShortDataType.dataType, UnsignedShortDataType.dataType,
            IntegerDataType.dataType, UnsignedIntegerDataType.dataType, LongDataType.dataType,
            UnsignedLongDataType.dataType, LongLongDataType.dataType, UnsignedLongLongDataType.dataType,
            FloatDataType.dataType, DoubleDataType.dataType, LongDoubleDataType.dataType,
            WideCharDataType.dataType, WideChar16DataType.dataType, WideChar32DataType.dataType,
            VoidDataType.dataType, ByteDataType.dataType, SignedByteDataType.dataType,
            Undefined1DataType.dataType, Undefined2DataType.dataType, Undefined4DataType.dataType,
            Undefined8DataType.dataType, DataType.DEFAULT,
        ).associateBy { it.pathName }

        private fun builtin(path: String) = BUILTINS[path] ?: error("no type $path")

        fun parse(text: String): StlLayouts {
            val records = linkedMapOf<String, Record>()
            var members: MutableList<List<String>>? = null
            for (line in text.lineSequence()) {
                if (line.isEmpty()) continue
                val fields = line.split('\t')
                if (line.startsWith("\t")) {
                    checkNotNull(members) { "member before any type: $line" }.add(fields.drop(1))
                } else {
                    members = mutableListOf()
                    records[fields[1]] = Record(fields[0].single(), fields.drop(1), members)
                }
            }
            return StlLayouts(records)
        }

        /** The bundled layouts [name] (one of [MsvcRuntime.BUNDLED]). */
        fun load(name: String): StlLayouts {
            require(name in MsvcRuntime.BUNDLED) { "no bundled layouts $name" }
            val stream = checkNotNull(StlLayouts::class.java.getResourceAsStream("/ghicpp/stl/$name.txt")) {
                "missing resource $name.txt"
            }
            return parse(stream.use { it.readBytes().toString(Charsets.UTF_8) })
        }
    }
}

/**
 * Fills the program's empty `std` structs from the runtime's [layouts]. Ghidra's Microsoft demangler
 * makes an empty placeholder for each class a demangled method belongs to, at the class's namespace path
 * under `/Demangler`, and the layouts file each type at that same path without it. So a placeholder
 * `/Demangler/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>` is replaced, at every
 * use, by the runtime's `/std/basic_string<…>`, and an empty one already at `/std/…` is filled in place.
 *
 * Runs in the caller's transaction.
 */
class MsvcStlApplier(private val program: Program, private val layouts: StlLayouts) {
    data class Result(val replaced: Int, val filled: Int)

    fun apply(): Result {
        val dtm = program.dataTypeManager
        val stubs = mutableListOf<Pair<Structure, Composite>>()
        dtm.allStructures.forEach { stub ->
            if (!stub.isNotYetDefined) return@forEach
            val path = archivePath(stub.categoryPath) ?: return@forEach
            val layout = layouts[DataTypePath(path, stub.name)] as? Composite ?: return@forEach
            if (!layout.isNotYetDefined) stubs.add(stub to layout)
        }
        if (stubs.isEmpty()) return Result(0, 0)

        // An empty struct already at the layout's path is filled in place by the conflict handler; a
        // placeholder under /Demangler is swapped for the resolved type everywhere it is used.
        val resolved = stubs.map { (stub, layout) ->
            stub to dtm.resolve(layout, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
        }
        val replacements = resolved.filter { (stub, type) -> stub !== type && dtm.contains(stub) }
            .map { (stub, type) -> stub as DataType to type }
        (dtm as DataTypeManagerDB).replaceDataTypesBatched(replacements)
        return Result(replacements.size, stubs.size - replacements.size)
    }

    companion object {
        private val ROOTS = setOf("std", "stdext")

        /** Where the layouts file the type a placeholder at [category] stands for; null outside std. */
        fun archivePath(category: CategoryPath): CategoryPath? {
            val names = category.pathElements.toList()
                .let { if (it.firstOrNull() == "Demangler") it.drop(1) else it }
            if (names.firstOrNull() !in ROOTS) return null
            return CategoryPath(CategoryPath.ROOT, names)
        }
    }
}
