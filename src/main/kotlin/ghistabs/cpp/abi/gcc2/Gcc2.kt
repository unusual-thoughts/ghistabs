package ghistabs.cpp.abi.gcc2

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.ShortDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghistabs.Demangler
import ghistabs.cpp.MemberDecl
import ghistabs.cpp.abi.CxxAbi
import ghistabs.cpp.abi.Structor
import ghistabs.cpp.abi.VtableRecord
import ghistabs.cpp.abi.gcc2.Gcc2.DEMANGLED_VTABLE_SUFFIX
import ghistabs.cpp.abi.itanium.Itanium
import ghistabs.cpp.leafName
import ghistabs.cpp.nameSegments
import ghistabs.cpp.qualifiedName
import ghistabs.namespaces

/**
 * gcc 2.x's symbol spellings: vtables, thunks, typeinfo and mangled members, and what Ghidra's demangler
 * makes of them. The vtable geometry is [Gcc2Abi]'s.
 */
object Gcc2 {
    // The marker between `_vt` and the mangled class is one of gdb's cplus_markers — `$`, or `.`
    // where the assembler forbids `$`, which is what the corpus binaries use. `-fvtable-thunks`
    // spells the whole prefix `__vt_` instead, with no marker.
    const val VTABLE_PREFIX = "_vt"
    const val THUNK_VTABLE_PREFIX = "__vt_"
    const val CPLUS_MARKERS = "$."

    /** What a.out prepends to every symbol, so `_vt$C` is stored as `__vt$C`. ELF prepends nothing. */
    const val USER_LABEL_PREFIX = "_"

    // cplus-dem.c spells a gcc 2.x vtable "<class> virtual table"; DemangledObject.setName replaces
    // the spaces, so the leaf arrives as "<class>_virtual_table" with the scope in the namespace.
    private const val DEMANGLED_VTABLE_SUFFIX = "_virtual_table"

    /** Prefix of the fields a gcc 2.x vftable struct gives its reserved entry. */
    const val RESERVED = "__reserved"

    /** A this-adjusting thunk, `__thunk_<delta>_<target>` (cp/method.c make_thunk). */
    const val THUNK_PREFIX = "__thunk_"

    // The artificial `int __in_chrg` on constructors of classes with virtual bases and on destructors
    // (cp-tree.h IN_CHARGE_NAME), like `this` not the source's.
    const val IN_CHARGE = "__in_chrg"

    /** A [THUNK_PREFIX] linkage name, [USER_LABEL_PREFIX]ed or not. Ghidra makes it a plain function. */
    fun looksLikeThunk(symbolName: String) =
        symbolName.startsWith(THUNK_PREFIX) || symbolName.removePrefix(USER_LABEL_PREFIX).startsWith(THUNK_PREFIX)

    /** A gcc 2.x vtable symbol, with or without thunks, primary or secondary. */
    fun looksLikeVtable(symbolName: String) = vtableTail(symbolName) != null

    /**
     * A gcc 2.x typeinfo object or the function returning it: `__ti` or `__tf` then the mangled type
     * (`cp/rtti.c`), as in `__ti4Base`. Only a class's mangling matches.
     */
    fun isTypeinfoName(name: String) = TYPEINFO_NAME.matches(name)

    /** A gcc 2.x destructor's linkage name: `_` then a cplus_marker, `_`, and the class (`_._5Named`). */
    fun isDtorName(name: String) = name.length > 3 && name[0] == '_' && name[1] in MARKERS && name[2] == '_'

    /**
     * A `-fvtable-thunks` vtable symbol (`__vt_`), whose entries are bare function pointers; without thunks
     * each is `{short delta; short index; void *pfn;}` ([Gcc2Thunks], [Gcc2Plain]). It is a flag rather than
     * a version, so only the symbol tells: every i386 gcc up to 2.7.2.3 builds without thunks, and later
     * ones by target default.
     */
    fun looksLikeThunkVtable(symbolName: String) = symbolName.startsWith(THUNK_VTABLE_PREFIX)

    /**
     * A gcc 2.x vtable symbol naming a class's own table, not a base's secondary one: no second marker in
     * the tail, as `_vt.4Left.4Base` has. Read off the mangled form, because a nested class demangles the
     * same way (`Outer::Inner`) but mangles as `Q2…`, never with a marker.
     */
    fun looksLikePrimaryVtable(symbolName: String) = vtableTail(symbolName)?.none { it in CPLUS_MARKERS } == true

    /** The qualified class a demangled gcc 2.x vtable names (`Foo_virtual_table`), or null if [obj] is none. */
    fun demangledVtableClass(obj: DemangledObject): String? {
        val leaf = obj.name?.removeSuffix(DEMANGLED_VTABLE_SUFFIX)?.takeIf { it != obj.name } ?: return null
        return (obj.namespaces + leaf).qualifiedName
    }

    /**
     * A member's symbol up to its parameters, as gdb's `gdb_mangle_name` composes it: `__9TiXmlNode` for a
     * constructor, `_._9TiXmlNode` for the destructor, `FirstChild__C9TiXmlNode` for the rest. A stab's
     * physname field holds only the parameters that follow, if anything.
     */
    fun physnamePrefix(memberName: String, className: String, isConst: Boolean, isVolatile: Boolean): String {
        val mangledClass = mangleClassName(className)
        val leaf = className.leafName
        return when (memberName) {
            leaf -> "__$mangledClass"
            "~$leaf" -> "_._$mangledClass"
            else -> memberName + "__" + cv(isConst, isVolatile) + mangledClass
        }
    }

    /**
     * A class name as gcc 2.x mangles it: `9TiXmlNode`, and nested `Q25Outer5Inner`, the count bracketed
     * above nine (`Q_10_…`). No `_` follows a single-digit count: the demangler accepts one, but gcc never
     * emits it, and these names are looked up.
     */
    fun mangleClassName(name: String): String {
        val parts = name.nameSegments
        val joined = parts.joinToString("") { "${it.length}$it" }
        return when {
            parts.size == 1 -> joined
            parts.size <= 9 -> "Q${parts.size}$joined"
            else -> "Q_${parts.size}_$joined"
        }
    }

    /**
     * The class and base a gcc 2.x secondary vtable symbol names: `iostream` and `ios` for
     * `_vt.8iostream.3ios`. Null for any other symbol, and for a deeper path through bases. A class whose
     * polymorphic bases are all virtual has only these. The split is read off the mangled form, which
     * tells `Outer::Inner`'s `ios` table from `Outer`'s `Inner::ios` one.
     */
    fun secondaryVtableClasses(symbolName: String): Pair<String, String>? {
        val tail = vtableTail(symbolName) ?: return null
        val cls = tail.takeWhile { it !in MARKERS }
        if (cls == tail || tail.substring(cls.length + 1).any { it in MARKERS }) return null
        val scopes = scopeCount(cls) ?: return null
        val names = Demangler.of("$VTABLE_PREFIX.$tail")?.let(::demangledVtableClass)?.nameSegments
            ?.takeIf { it.size > scopes } ?: return null
        return names.take(scopes).qualifiedName to names.drop(scopes).qualifiedName
    }

    /** How many scopes the mangled class [mangled] spells: the count of a `Q<n>` or `Q_<n>_`, else one. */
    private fun scopeCount(mangled: String): Int? = when {
        !mangled.startsWith("Q") -> 1
        mangled.getOrNull(1) == '_' -> mangled.drop(2).takeWhile(Char::isDigit).toIntOrNull()
        else -> mangled.getOrNull(1)?.digitToIntOrNull()
    }

    /** A name gcc made up for an anonymous type (`$_0`, `._0`), which is no namespace. */
    fun isCompilerGeneratedName(name: String) = name.firstOrNull() in MARKERS

    /**
     * A name gcc 2.x mangled: a member as [physnamePrefix] composes it (`Accept__C12TiXmlElement`,
     * `_._9TiXmlNode`), a function (`sum__Fie`) or function template (`max2__H1Z…`), or a static data
     * member (`_5Shape.count`). A class's length must fit in the name: the shape alone also matches C
     * statics such as `initialized___6`, and [CxxAbi.prevailing] lets one symbol decide.
     */
    fun isProbablyMangled(name: String) = MANGLED_FUNCTION_TAIL.containsMatchIn(name) ||
        MANGLED_MEMBER_TAIL.findAll(name).any { m -> m.range.last + 1 + m.groupValues[1].toInt() <= name.length } ||
        MANGLED_STATIC_MEMBER.find(name)?.let { m ->
            val end = m.range.last + 1 + m.groupValues[1].toInt()
            end < name.length && name.indexOfAny(charArrayOf('.', '$'), end) >= 0
        } == true

    /**
     * The symbol of a member whose physname starts with its own class (`t…` or `Q…`, as gdb reads it):
     * `push__t5Stack2Z5Pointi2RC5Point`. Null otherwise. Only a candidate, as a template or nested
     * argument starts that way too.
     */
    fun classQualifiedPhysname(memberName: String, physname: String, isConst: Boolean, isVolatile: Boolean) =
        physname.takeIf { it.firstOrNull() == 't' || it.firstOrNull() == 'Q' }
            ?.let { memberName + "__" + cv(isConst, isVolatile) + it }

    /** The mangled class name a gcc 2.x vtable symbol carries, or null if [symbolName] isn't one. */
    private fun vtableTail(symbolName: String): String? = when {
        symbolName.startsWith(THUNK_VTABLE_PREFIX) -> symbolName.removePrefix(THUNK_VTABLE_PREFIX)
        else -> plainVtableTail(symbolName) ?: plainVtableTail(symbolName.removePrefix(USER_LABEL_PREFIX))
    }

    /** What follows [VTABLE_PREFIX] and a cplus_marker, or null: `_vt.4Node` on ELF, `__vt$4Node` on a.out. */
    private fun plainVtableTail(symbolName: String): String? = symbolName
        .takeIf { it.startsWith(VTABLE_PREFIX) && it.getOrNull(VTABLE_PREFIX.length) in MARKERS }
        ?.substring(VTABLE_PREFIX.length + 1)

    private val MARKERS = CPLUS_MARKERS.toSet()

    // The optional leading `_` is a.out's [USER_LABEL_PREFIX].
    private val TYPEINFO_NAME = Regex("_?__t[if][0-9Qt].*")

    private fun cv(isConst: Boolean, isVolatile: Boolean) = (if (isConst) "C" else "") + (if (isVolatile) "V" else "")

    // `Q<n>` counts the nesting components and is not itself length-prefixed — `__Q217__class_type_info…`
    // is Q2 then the 17-character `__class_type_info`, so only the length run after it is checked.
    // A template class is `t` before its length, nested or not (`Q2t5Stack2Zii4_4Iter`).
    private val MANGLED_MEMBER_TAIL = Regex("""(?:_\._|__[CV]*)(?:Q[0-9]_?)?t?([0-9]+)""")

    // A static data member, `_` then the length-prefixed class, `.` (or `$`) then the member:
    // `_5Shape.count`, a.out's extra underscore in `__9TiXmlBase.entity`.
    private val MANGLED_STATIC_MEMBER = Regex("""^__?(?:Q[0-9]_?)?t?([0-9]+)""")

    // The `[^_]` keeps a name that merely starts with underscores (`___FRAME_END__`) out.
    private val MANGLED_FUNCTION_TAIL = Regex("""[^_]__(?:F.|H[0-9]+Z)""")
}

/**
 * A gcc 2.x vtable: a reserved entry of 8 bytes on 32-bit (`cp/class.c:skip_rtti_stuff`), then the slots.
 * The vptr holds the record start, and a call skips the reserved entry itself.
 */
sealed interface Gcc2Abi : CxxAbi {
    /** Pointer-wide words per entry: a bare `pfn`, or `{delta, index}` then `pfn`, which comes last. */
    val entryWords: Int

    /** The reserved entry before the first virtual's (`cp/class.c:skip_rtti_stuff`). */
    fun headerBytes(ptrSize: Int) = 2L * ptrSize

    override val primaryVptrOffset get() = null

    /** A record with no header of its own: the reserved entry is part of the `_vftable` struct. */
    override fun recordAt(program: Program, at: Address) = VtableRecord(at, null, this)

    /** Past the reserved entry, each `pfn` last in its entry. */
    override fun slotOffsets(ptrSize: Int) =
        generateSequence(headerBytes(ptrSize) + (entryWords - 1L) * ptrSize) { it + entryWords.toLong() * ptrSize }

    /** A stab's `*<n>` counts entries from the record start, so the reserved ones come first. */
    override fun reservedEntries(ptrSize: Int) = (headerBytes(ptrSize) / (entryWords.toLong() * ptrSize)).toInt()

    /** `new` calls libgcc's `__builtin_new`; a program's own global `operator new` is `__nw__FUi`. */
    override val mangledOperatorNew get() = setOf("__builtin_new", "__nw__FUi", "__nw__FUl")

    /** A destructor in charge of freeing calls `__builtin_delete`; a program's own is `__dl__FPv`. */
    override val mangledOperatorDelete get() = setOf("__builtin_delete", "__dl__FPv")

    override fun isPrimaryVtable(symbolName: String) = Gcc2.looksLikePrimaryVtable(symbolName)

    override fun demangledVtableClass(obj: DemangledObject) = Gcc2.demangledVtableClass(obj)

    /** `__as` is how gcc 2.x spells `operator=` in a stab, and in the symbol it composes from it. */
    override val assignmentOperatorName get() = "__as"

    override fun isProbablyMangled(name: String) = Gcc2.isProbablyMangled(name)

    /**
     * The stated physname, then the symbol composed from it: a gcc 2.x physname is only the mangled
     * parameters (`PCc`), appended to [Gcc2.physnamePrefix] as gdb does.
     */
    override fun physnameCandidates(m: MemberDecl, className: String) = listOfNotNull(
        m.mangled,
        m.mangled?.let { Gcc2.classQualifiedPhysname(m.name, it, m.isConst, m.isVolatile) },
        Gcc2.physnamePrefix(m.name, className, m.isConst, m.isVolatile) + m.mangled.orEmpty(),
    )

    /** By [Gcc2.physnamePrefix]'s forms; without [className] only a destructor tells, as `__` starts too much. */
    override fun structorOf(mangled: String, className: String?): Gcc2Structor? {
        if (className == null) return Gcc2Structor.DESTRUCTOR.takeIf { Gcc2.isDtorName(mangled) }
        val mangledClass = Gcc2.mangleClassName(className)
        return Gcc2Structor.entries.firstOrNull { mangled.startsWith("${it.prefix}$mangledClass") }
    }
}

/** `__vt_`: the `this` adjustment moved into a thunk, so an entry is the pfn. */
data object Gcc2Thunks : Gcc2Abi {
    override val entryWords get() = 1

    override fun looksLikeVtable(symbolName: String) = Gcc2.looksLikeThunkVtable(symbolName)

    override fun vtableCandidates(className: String) =
        listOf("${Gcc2.THUNK_VTABLE_PREFIX}${Gcc2.mangleClassName(className)}")

    override fun Structure.addReservedHeader() {
        add(IntegerDataType.dataType, Gcc2.RESERVED + "_offset", "reserved: offset/tdesc entry")
        add(IntegerDataType.dataType, Gcc2.RESERVED + "_tdesc", "reserved: tdesc pointer")
    }
}

/** `_vt.`/`_vt$` (`__vt.` on a.out): `{delta, index, pfn}` entries, the pfn in the second word. */
data object Gcc2Plain : Gcc2Abi {
    /** `delta` and `index` share one word, a `short` each (unless `-fhuge-objects`). */
    override val entryWords get() = 2

    override fun looksLikeVtable(symbolName: String) =
        Gcc2.looksLikeVtable(symbolName) && !Gcc2.looksLikeThunkVtable(symbolName)

    override fun vtableCandidates(className: String) = Gcc2.mangleClassName(className).let { m ->
        Gcc2.CPLUS_MARKERS.flatMap { marker ->
            listOf("", Gcc2.USER_LABEL_PREFIX).map { "$it${Gcc2.VTABLE_PREFIX}$marker$m" }
        }
    }

    override fun Structure.addReservedHeader() {
        add(ShortDataType.dataType, Gcc2.RESERVED + "__delta", "reserved entry: delta")
        add(ShortDataType.dataType, Gcc2.RESERVED + "__index", "reserved entry: index")
        add(IntegerDataType.dataType, Gcc2.RESERVED + "__pfn", "reserved entry: pfn")
    }

    override fun Structure.addEntryAdjustment(slot: Int) {
        add(ShortDataType.dataType, "slot${slot}__delta", "this-adjustment for slot $slot")
        add(ShortDataType.dataType, "slot${slot}__index", "unused; gcc 2.x always emits 0")
    }
}

/** A gcc 2.x constructor or destructor: one of each per class, the destructor freeing when told to. */
enum class Gcc2Structor(val prefix: String, override val isDestructor: Boolean) : Structor {
    DESTRUCTOR("_._", true),
    CONSTRUCTOR("__", false),
    ;

    override val isDeleting get() = false

    override fun displayName(className: String) = if (isDestructor) "~$className" else className
}
