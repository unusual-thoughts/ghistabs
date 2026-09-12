package ghistabs.materialize.abi

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.ShortDataType
import ghidra.program.model.data.Structure
import ghistabs.materialize.abi.Gcc2.DEMANGLED_VTABLE_SUFFIX

/**
 * Pre-Itanium gcc 2.x C++ ABI facts: the vtable symbol spellings and what the deprecated demangler
 * back end makes of them. The counterpart to [Itanium] for the WordPerfect/libstdc++-2.8.1 corpus,
 * and separate from it because none of it *is* Itanium — different names, no typeinfo, and the
 * record geometry in [CxxAbi].
 */
object Gcc2 {
    // The marker between `_vt` and the mangled class is one of gdb's cplus_markers — `$`, or `.`
    // where the assembler forbids `$`, which is what the corpus binaries use. `-fvtable-thunks`
    // spells the whole prefix `__vt_` instead, with no marker.
    const val VTABLE_PREFIX = "_vt"
    const val THUNK_VTABLE_PREFIX = "__vt_"
    const val CPLUS_MARKERS = "\$."

    // cplus-dem.c spells a gcc 2.x vtable "<class> virtual table"; DemangledObject.setName replaces
    // the spaces, so the leaf arrives as "<class>_virtual_table" with the scope in the namespace.
    private const val DEMANGLED_VTABLE_SUFFIX = "_virtual_table"

    /** Prefix for the non-slot fields of a gcc 2.x vftable — its reserved header entry. */
    const val RESERVED = "__reserved"

    /**
     * String-level pre-filter for a gcc 2.x vtable symbol — the gcc 2.x parallel to
     * [Itanium.looksLikeZtv], and just as cheap. Such a record carries none of the Itanium fixed
     * words; see [CxxAbi] for what it carries instead.
     */
    fun looksLikeVtable(symbolName: String) = vtableTail(symbolName) != null

    /**
     * The `-fvtable-thunks` spelling, which decides the *entry width*. gcc 2.95.3 `cp/decl.c`: with
     * thunks an entry is a bare function pointer, the `this` adjustment having moved into a thunk;
     * without them it is the record `{short delta; short index; void *pfn;}`, twice as wide. The
     * header is 8 bytes either way — `cp/class.c:skip_rtti_stuff` reserves two *entries* with thunks
     * and one without — which on 32-bit is what [Itanium.vtablePrefixBytes] already computes.
     */
    fun looksLikeThunkVtable(symbolName: String) = symbolName.startsWith(THUNK_VTABLE_PREFIX)

    /**
     * A gcc 2.x vtable symbol naming a class's *own* table, which is the only kind a lookup by class
     * name wants. A second marker in the tail separates a **base**, naming that base's secondary
     * table inside the first class: `cv_mscom_elf_i386_gcc281` has `_vt.14CExposedStream` alongside
     * `_vt.14CExposedStream.11PRevertable`, and carries `_vt.11PRevertable` separately as
     * PRevertable's own — so the two-segment name is a third object, distinct from either.
     *
     * The screen has to be on the mangled form, because the demangled one cannot tell: a genuinely
     * nested class gives the same `Outer::Inner_virtual_table`. gcc 2.x spells a nested class with
     * the `Q` form (`Q2_6Outer5Inner`), never marker-separated, so the mangled name is unambiguous.
     */
    fun looksLikePrimaryVtable(symbolName: String) = vtableTail(symbolName)?.none { it in CPLUS_MARKERS } == true

    /**
     * Qualified class name of a demangled gcc 2.x vtable object, which is not an address table at
     * all: the leaf carries [DEMANGLED_VTABLE_SUFFIX] and any enclosing scope is in the namespace
     * chain. Null if [obj] is not one.
     */
    fun demangledVtableClass(obj: DemangledObject): String? {
        val leaf = obj.name?.removeSuffix(DEMANGLED_VTABLE_SUFFIX)?.takeIf { it != obj.name } ?: return null
        return (namespaceChain(obj) + leaf).joinToString("::")
    }

    /**
     * The physname gcc 2.x *would* have emitted for a member — gdb's `gdb_mangle_name`, and needed
     * for the same reason: the stab's physname field is routinely empty (98 of tinyxml's 274 method
     * entries are `name::type;:;<vis><cv><virt>`), leaving the mangled name to be reconstructed from
     * the class, the member name and the cv-qualifier the stab *does* state.
     *
     * Returned as a **prefix**, because the parameter mangling that follows is exactly what a stub
     * method does not carry: `Accept__C12TiXmlComment` + `P12TiXmlVisitor`. A nil-ary member's
     * prefix is its whole symbol. All three forms are as `tinyxml_aout_gcc295.o` spells them —
     * `__11TiXmlStringPCc`, `_._9TiXmlNode`, `FirstChild__C9TiXmlNodePCc`.
     */
    fun physnamePrefix(memberName: String, className: String, isConst: Boolean, isVolatile: Boolean): String {
        val mangledClass = mangleClassName(className)
        val leaf = className.substringAfterLast("::")
        return when {
            memberName == leaf -> "__$mangledClass"
            memberName == "~$leaf" -> "_._$mangledClass"
            else -> memberName + "__" + (if (isConst) "C" else "") + (if (isVolatile) "V" else "") + mangledClass
        }
    }

    /**
     * gcc 2.x class-name mangling: `TiXmlNode` → `9TiXmlNode`, nesting → `Q<n>_` then each part
     * length-prefixed (`Outer::Inner` → `Q2_5Outer5Inner`). The simple case agrees with Itanium's,
     * the nested one does not — see [Itanium.ztvCandidates].
     */
    fun mangleClassName(name: String): String {
        val parts = name.split("::")
        val joined = parts.joinToString("") { "${it.length}$it" }
        return if (parts.size == 1) joined else "Q${parts.size}_$joined"
    }

    /**
     * A name gcc invented for an anonymous type: `$_0`/`._0`, whose members mangle with it
     * (`lldiv_t`'s ctor is `__3._6`). The scope such a name states is a label, not a namespace.
     */
    fun isCompilerGeneratedName(name: String) = name.firstOrNull() in MARKERS

    /**
     * A name gcc 2.x mangled, recognised by mirroring what [physnamePrefix] composes: `__` then the
     * cv-qualifier then the length-prefixed class (`Accept__C12TiXmlElement`, `__as__11TiXmlString`,
     * `__11TiXmlStringPCc`), or the `_._` dtor form. A plain C symbol has no such run — the `__` has
     * to be followed by the length digit or a `Q`, which is what keeps `__vt_9TiXmlNode` and
     * `__errno_location` out.
     */
    fun isProbablyMangled(name: String) = name.startsWith("_._") || MANGLED_MEMBER_TAIL.containsMatchIn(name)

    /** The mangled class name a gcc 2.x vtable symbol carries, or null if [symbolName] isn't one. */
    private fun vtableTail(symbolName: String): String? = when {
        symbolName.startsWith(THUNK_VTABLE_PREFIX) -> symbolName.removePrefix(THUNK_VTABLE_PREFIX)

        symbolName.startsWith(VTABLE_PREFIX) && symbolName.getOrNull(VTABLE_PREFIX.length) in MARKERS ->
            symbolName.substring(VTABLE_PREFIX.length + 1)

        else -> null
    }

    private val MARKERS = CPLUS_MARKERS.toSet()

    private val MANGLED_MEMBER_TAIL = Regex("""__[CV]*(?:[0-9]|Q[0-9])""")
}

/** [obj]'s enclosing scopes, outermost first. */
internal fun namespaceChain(obj: DemangledObject) =
    generateSequence(obj.namespace) { it.namespace }.map { it.name }.toList().asReversed()

/**
 * gcc 2.95.3, `cp/class.c:skip_rtti_stuff`: two pointer header entries with thunks, one 8-byte
 * record without, so 8 bytes either way on 32-bit. The vptr holds the record start and the call
 * site skips the header (`tinyxml_aout_gcc295.o` dispatches through `add eax,0x8`).
 */
sealed interface Gcc2Abi : CxxAbi {
    override fun stride(ptrSize: Int) = ptrSize.toLong()
    override fun pfnOffset(ptrSize: Int) = 0L
    override fun headerBytes(ptrSize: Int) = 2L * ptrSize

    /** gcc 2.x emits no typeinfo pointer, so no rtti word locates the address point. */
    override val hasRttiHeader get() = false
    override val vptrAtRecordStart get() = true

    override fun isPrimaryVtable(symbolName: String) = Gcc2.looksLikePrimaryVtable(symbolName)

    override fun demangledVtableClass(obj: DemangledObject) = Gcc2.demangledVtableClass(obj)

    /** `__as` is how gcc 2.x spells `operator=` in a stab, and in the symbol it composes from it. */
    override val assignmentOperatorName get() = "__as"

    override fun isProbablyMangled(name: String) = Gcc2.isProbablyMangled(name)

    /**
     * A gcc 2.x stab does not put a symbol in its physname field — it puts the mangled *argument
     * list*, which is what gdb's `gdb_mangle_name` concatenates onto `<name>__<cv><class>`.
     * `tinyxml_aout_gcc295.o` states `""` and `"PCc"` for FirstChild's two overloads and carries
     * `FirstChild__C9TiXmlNode` and `FirstChild__C9TiXmlNodePCc`, so the fragment is exactly what
     * tells them apart: composing it gives one candidate, not a prefix to search under.
     *
     * The composed form is skipped for an Itanium-mangled physname, so a COMDAT-dropped `_ZN…`
     * appearing in a gcc 2.x link does not get a bogus second lookup.
     */
    override fun physnameCandidates(
        memberName: String,
        className: String,
        isConst: Boolean,
        isVolatile: Boolean,
        stated: String?,
    ) = listOfNotNull(
        stated,
        if (stated == null || !Itanium.isProbablyMangled(stated)) {
            Gcc2.physnamePrefix(memberName, className, isConst, isVolatile) + stated.orEmpty()
        } else {
            null
        },
    )

    /** The inverse of [Gcc2.physnamePrefix]'s ctor/dtor forms — `__9TiXmlNode`, `_._9TiXmlNode`. */
    override fun specialMemberDisplayName(mangled: String, className: String): String? {
        val mangledClass = Gcc2.mangleClassName(className)
        return when {
            mangled.startsWith("_._$mangledClass") -> "~$className"
            mangled.startsWith("__$mangledClass") -> className
            else -> null
        }
    }
}

/** `__vt_`: the `this` adjustment moved into a thunk, so an entry is the pfn. */
data object Gcc2Thunks : Gcc2Abi {
    override fun looksLikeVtable(symbolName: String) = Gcc2.looksLikeThunkVtable(symbolName)

    override fun vtableCandidates(className: String) =
        listOf("${Gcc2.THUNK_VTABLE_PREFIX}${Gcc2.mangleClassName(className)}")

    override fun Structure.addReservedHeader() {
        add(IntegerDataType.dataType, Gcc2.RESERVED + "_offset", "reserved: offset/tdesc entry")
        add(IntegerDataType.dataType, Gcc2.RESERVED + "_tdesc", "reserved: tdesc pointer")
    }
}

/** `_vt.`/`_vt$`: `{delta, index, pfn}` entries, twice as wide, with pfn in the second word. */
data object Gcc2Plain : Gcc2Abi {
    override fun stride(ptrSize: Int) = 2L * ptrSize

    /** `delta` and `index` are a `short` each: one 32-bit word. (`-fhuge-objects` would widen
     *  both to `long`; no corpus binary uses it.) */
    override fun pfnOffset(ptrSize: Int) = ptrSize.toLong()

    override fun looksLikeVtable(symbolName: String) =
        Gcc2.looksLikeVtable(symbolName) && !Gcc2.looksLikeThunkVtable(symbolName)

    override fun vtableCandidates(className: String) = Gcc2.mangleClassName(className)
        .let { m -> Gcc2.CPLUS_MARKERS.map { "${Gcc2.VTABLE_PREFIX}$it$m" } }

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
