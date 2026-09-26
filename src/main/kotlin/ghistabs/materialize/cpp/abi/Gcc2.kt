package ghistabs.materialize.cpp.abi

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.ShortDataType
import ghidra.program.model.data.Structure
import ghistabs.materialize.cpp.abi.Gcc2.DEMANGLED_VTABLE_SUFFIX
import ghistabs.namespaces
import ghistabs.parse.TypeDecl.Aggregate.Method
import ghistabs.parse.leafName
import ghistabs.parse.nameSegments
import ghistabs.parse.qualifiedName

/**
 * Pre-Itanium gcc 2.x C++ ABI facts: the vtable symbol spellings and what the deprecated demangler
 * back end makes of them. The counterpart to [Itanium] for the libstdc++-2.8.1 corpus,
 * and separate from it because none of it *is* Itanium — different names, no typeinfo, and the
 * record geometry in [CxxAbi].
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

    /** Prefix for the non-slot fields of a gcc 2.x vftable — its reserved header entry. */
    const val RESERVED = "__reserved"

    /**
     * String-level pre-filter for a gcc 2.x vtable symbol — the gcc 2.x parallel to
     * [Itanium.looksLikeVtable], and just as cheap. Such a record carries none of the Itanium fixed
     * words; see [CxxAbi] for what it carries instead.
     */
    fun looksLikeVtable(symbolName: String) = vtableTail(symbolName) != null

    /**
     * The `-fvtable-thunks` spelling, which decides the *entry width*. gcc 2.95.3 `cp/decl.c`: with
     * thunks an entry is a bare function pointer, the `this` adjustment having moved into a thunk;
     * without them it is the record `{short delta; short index; void *pfn;}`, twice as wide. The
     * header is 8 bytes either way — `cp/class.c:skip_rtti_stuff` reserves two *entries* with thunks
     * and one without — which on 32-bit is what [Itanium.vtablePrefixBytes] already computes.
     *
     * The choice is a *flag*, never a version, which is why it has to be read off the binary. In
     * `cp/decl.c` the thunk branch builds `build_pointer_type` of a FUNCTION_TYPE returning int, and
     * the other builds the RECORD_TYPE — so the stabs state it outright: `__vtbl_ptr_type` is
     * `*(0,23)=f(0,1)` with thunks and `s8{__delta,__index,__pfn,__delta2}` without (the last field
     * an invisible union over `__pfn`, which is why both sit at bit 32).
     *
     * gcc 2.7.2.3's `cp/decl2.c` has `int flag_vtable_thunks;` — unconditionally off, with the
     * comment "The default is off now, but will be on later" — and its `config/i386/unix.h` defines
     * no `ASM_OUTPUT_MI_THUNK` at all, so every i386 build up to and including 2.7.2.3 is the record
     * form. Mainline then made it a target default (`#ifdef ASM_OUTPUT_MI_THUNK` in 1996, then
     * `DEFAULT_VTABLE_THUNKS`, which `config/linux.h` set to 1 for non-libc5 Linux on 1997-08-27);
     * the 2.7.2.x maintenance branch never took those, which is why 2.7.2.3 post-dates the switch
     * and still emits the old shape.
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
        return (obj.namespaces + leaf).qualifiedName
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
        val leaf = className.leafName
        return when (memberName) {
            leaf -> "__$mangledClass"
            "~$leaf" -> "_._$mangledClass"
            else -> memberName + "__" + cv(isConst, isVolatile) + mangledClass
        }
    }

    /**
     * gcc 2.x class-name mangling: `TiXmlNode` → `9TiXmlNode`, nesting → the component count then
     * each part length-prefixed (`Outer::Inner` → `Q25Outer5Inner`). The simple case agrees with
     * Itanium's, the nested one does not — see [Itanium.vtableCandidates].
     *
     * No underscore after a single-digit count. `libiberty/cplus-dem.c:demangle_qualified` *accepts*
     * one — "said to be for ARM-qualified names… perhaps cfront uses one" — which is why the wrong
     * form still demangles, and why it has to be got right here instead: these names are composed to
     * be looked up, and `Q2_17__class_type_info9base_info` is not the symbol gcc emitted.
     * `cv_mscom_elf_i386_gcc281` spells it `Q217__class_type_info9base_info`. Above nine components
     * the count is bracketed instead (`Q_10_`), which is the same source's `case '_'`.
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
     * A name gcc invented for an anonymous type: `$_0`/`._0`, whose members mangle with it
     * (`lldiv_t`'s ctor is `__3._6`). The scope such a name states is a label, not a namespace.
     */
    fun isCompilerGeneratedName(name: String) = name.firstOrNull() in MARKERS

    /**
     * A name gcc 2.x mangled, recognised by mirroring what [physnamePrefix] composes: `__` then the
     * cv-qualifier then the length-prefixed class (`Accept__C12TiXmlElement`, `__as__11TiXmlString`,
     * `__11TiXmlStringPCc`, a template class's `push__t5Stack2Z5Pointi2RC5Point`), or the `_._` dtor
     * form. Or a free function, `__F` then its arguments (`sum__Fie`), or a template one, `__H` then
     * its argument count (`max2__H1Zs_X01X01_X01`).
     *
     * A member's length has to be *satisfied*, not merely present. One symbol is enough to settle a
     * whole binary's ABI (see [CxxAbi.prevailing]), and the shape alone is not rare enough for that:
     * `fxwpf_som_parisc_gcc` holds no C++ at all, yet its static-local `initialized___6` matches the
     * shape while claiming six characters that are not there. A function has no length to check;
     * across the corpus its shape matches only `__imp__FindAtomA@4`-style imports, in Itanium
     * binaries that outvote them by thousands.
     */
    fun isProbablyMangled(name: String) = MANGLED_FUNCTION_TAIL.containsMatchIn(name) ||
        MANGLED_MEMBER_TAIL.findAll(name).any { m -> m.range.last + 1 + m.groupValues[1].toInt() <= name.length }

    /**
     * The symbol for a member whose physname already carries its class, or null for one that does
     * not. gdb's `gdb_mangle_name`: a physname opening on `t` or `Q` "already includes the class
     * name", so the symbol is `<name>__<cv>` + physname — `push__t5Stack2Z5Pointi2RC5Point` from
     * the stated `t5Stack2Z5Pointi2RC5Point`. Those letters also open a template or nested
     * *argument*, which is why this is one candidate among [physnamePrefix]'s rather than a
     * replacement for it.
     */
    fun classQualifiedPhysname(memberName: String, physname: String, isConst: Boolean, isVolatile: Boolean) =
        physname.takeIf { it.firstOrNull() == 't' || it.firstOrNull() == 'Q' }
            ?.let { memberName + "__" + cv(isConst, isVolatile) + it }

    /** The mangled class name a gcc 2.x vtable symbol carries, or null if [symbolName] isn't one. */
    private fun vtableTail(symbolName: String): String? = when {
        symbolName.startsWith(THUNK_VTABLE_PREFIX) -> symbolName.removePrefix(THUNK_VTABLE_PREFIX)
        else -> plainVtableTail(symbolName) ?: plainVtableTail(symbolName.removePrefix(USER_LABEL_PREFIX))
    }

    /**
     * [VTABLE_PREFIX] plus a cplus_marker, or null. Tried both as-is and with one leading underscore
     * removed, because a.out prepends the user label prefix to every symbol: the same class arrives
     * as `_vt.TiXmlNode` on ELF (`tinyxml_elf_gcc272.o`) and `__vt$TiXmlNode` on a.out
     * (`tinyxml_aout_gcc263.o`). Stripping cannot swallow a thunk table — that spelling is matched
     * first, and `_` is not a cplus_marker, so `__vt_9TiXmlNode` never reaches here.
     */
    private fun plainVtableTail(symbolName: String): String? = symbolName
        .takeIf { it.startsWith(VTABLE_PREFIX) && it.getOrNull(VTABLE_PREFIX.length) in MARKERS }
        ?.substring(VTABLE_PREFIX.length + 1)

    private val MARKERS = CPLUS_MARKERS.toSet()

    private fun cv(isConst: Boolean, isVolatile: Boolean) = (if (isConst) "C" else "") + (if (isVolatile) "V" else "")

    // `Q<n>` counts the nesting components and is not itself length-prefixed — `__Q217__class_type_info…`
    // is Q2 then the 17-character `__class_type_info`, so only the length run after it is checked.
    // A template class is `t` before its length, nested or not (`Q2t5Stack2Zii4_4Iter`).
    private val MANGLED_MEMBER_TAIL = Regex("""(?:_\._|__[CV]*)(?:Q[0-9]_?)?t?([0-9]+)""")

    // The `[^_]` keeps a name that merely starts with underscores (`___FRAME_END__`) out.
    private val MANGLED_FUNCTION_TAIL = Regex("""[^_]__(?:F.|H[0-9]+Z)""")
}

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
     * Composed unconditionally: the caller tries the stated name first and stops at the first hit,
     * so a physname that is already a whole symbol resolves before this one is ever looked up.
     */
    override fun physnameCandidates(m: Method<*>, className: String) = listOfNotNull(
        m.mangled,
        m.mangled?.let { Gcc2.classQualifiedPhysname(m.name, it, m.isConst, m.isVolatile) },
        Gcc2.physnamePrefix(m.name, className, m.isConst, m.isVolatile) + m.mangled.orEmpty(),
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

/**
 * `_vt.`/`_vt$` — and `__vt.`/`__vt$` once a.out has prefixed them: `{delta, index, pfn}` entries,
 * twice as wide, with pfn in the second word.
 */
data object Gcc2Plain : Gcc2Abi {
    override fun stride(ptrSize: Int) = 2L * ptrSize

    /** `delta` and `index` are a `short` each: one 32-bit word. (`-fhuge-objects` would widen
     *  both to `long`; no corpus binary uses it.) */
    override fun pfnOffset(ptrSize: Int) = ptrSize.toLong()

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
