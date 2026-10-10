package ghistabs.hierarchy

import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.VariableUtilities
import ghidra.program.model.symbol.*
import ghistabs.Demangler
import ghistabs.importer.ClassHierarchyRecord
import ghistabs.importer.MemberAttrs
import ghistabs.isInjected
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.*
import ghistabs.parse.Access
import ghistabs.parse.VirtKind
import ghistabs.parse.nameSegments
import ghistabs.readPointer
import kotlinx.serialization.Serializable

/**
 * Every class the program knows, with its direct bases, as the Class Hierarchy window shows them.
 *
 * Two sources, never mixed for one class: the stabs import's [ClassHierarchyRecord], exact down to
 * virtuality and access, gcc 2.x included; and, for a class the stabs never described but the vtable
 * sweep laid a `vftable` for, its Itanium typeinfo, when the program has one. A class with neither is
 * still listed, as a root, so the sweep's finds all show.
 *
 * Plain data, so it serializes: classes name each other by namespace id ([get] resolves one), and the
 * program's objects are kept as what finds them again, an address's text and a datatype id.
 */
@Serializable
data class ClassHierarchy(val classes: List<ClassInfo>) {
    enum class Origin {
        /** Described by the stabs: the import recorded its bases. */
        STABS,

        /** Laid by the vtable sweep, bases read off its `_ZTI` typeinfo. */
        SWEPT_RTTI,

        /** Laid by the vtable sweep with no typeinfo to read: bases unknown. */
        SWEPT,
    }

    /** A direct base: the class it names ([targetId]), if the program has one for it, else only its [name]. */
    @Serializable
    data class BaseRef(val name: String, val targetId: Long?, val isVirtual: Boolean, val access: Access?)

    /**
     * A function or label in the class's namespace, as the Symbol Tree lists it. An overloaded function
     * is spelled with its [parameters], `this` and the return type left out so overloads line up. [attrs]
     * are what the stabs said of it, else what the program shows; none for a vtable or other ABI object.
     */
    @Serializable
    data class Member(
        val name: String,
        val address: String,
        val kind: MemberKind,
        val signature: String? = null,
        val parameters: String? = null,
        val isOverloaded: Boolean = false,
        val attrs: MemberAttrs? = null,
        /** Which of its constructor's or destructor's variants it is: several when gcc aliased them. */
        val variants: List<StructorVariant> = emptyList(),
    ) {
        val label: String get() = (if (isOverloaded && parameters != null) name + parameters else name) +
            variants.takeIf { it.isNotEmpty() }?.joinToString(", ", " [", "]") { it.label }.orEmpty()
    }

    enum class MemberKind {
        /**
         * A vtable: our `vftable` / `internal_vftable` / `vftable_for_<Base>` and their `construction-`
         * spellings, or the demangler's `vtable`, `VTT`, `construction-vtable`.
         */
        VTABLE,

        /** Any other Itanium special name (`_ZT*`, `_ZG*`): `typeinfo`, `typeinfo-name`, guard variables. */
        ABI,
        FUNCTION,
        THUNK,

        /** Any other label: a static data member, by the stabs' word or not. */
        LABEL,
    }

    /** A class deriving from another, by the base clause naming that other. */
    data class Derived(val cls: ClassInfo, val clause: BaseRef)

    @Serializable
    data class ClassInfo(
        /** Its [GhidraClass] namespace's id. */
        val id: Long,
        /** That namespace's path, outermost first. */
        val path: List<String>,
        val origin: Origin,
        /** Where its primary `vftable` label sits, for a polymorphic class. */
        val vftable: String?,
        val vftableStructId: Long?,
        /** Its `_ZTI` typeinfo object, when the binary has one. */
        val typeinfo: String?,
        /** The struct the stabs laid for it, by datatype id, and its name (shorter, once typedef shortening ran). */
        val structId: Long?,
        val structName: String?,
        /** A slot of any of its vftables holds `__cxa_pure_virtual` (gcc 2.x: `__pure_virtual`). */
        val isAbstract: Boolean,
        /** Its functions and labels: vtables first, then the other ABI objects, then the rest by name. */
        val members: List<Member>,
        /** Its direct bases, in declaration order. */
        val bases: List<BaseRef>,
    ) {
        val name: String get() = path.last()
        val qualifiedName: String get() = path.joinToString("::")

        /** Where a double-click goes: the vtable, else the typeinfo. */
        val address: String? get() = vftable ?: typeinfo

        override fun toString() = qualifiedName
    }

    private val byId by lazy { classes.associateBy { it.id } }

    operator fun get(id: Long): ClassInfo? = byId[id]

    /** The class [base] names, when the program has one. */
    operator fun get(base: BaseRef): ClassInfo? = base.targetId?.let(byId::get)

    private val derived by lazy {
        classes.flatMap { cls -> cls.bases.mapNotNull { b -> this[b]?.let { it.id to Derived(cls, b) } } }
            .groupBy({ it.first }, { it.second })
            .mapValues { (_, list) -> list.sortedBy { it.cls.qualifiedName } }
    }

    /** The classes that name [cls] as a direct base, each with that base clause. */
    fun derivedOf(cls: ClassInfo): List<Derived> = derived[cls.id].orEmpty()

    /** No base the program has a class for: a root of the inverted tree. */
    fun isBasal(cls: ClassInfo) = cls.bases.none { this[it] != null }

    /**
     * Nothing to show but the name: no member, vtable, typeinfo, base or derived class. Mostly what g++
     * makes of a C struct or an SGI STL tag (`tm`, `__type_traits<bool>`): a class whose implicit
     * members it never emitted.
     */
    fun isEmpty(cls: ClassInfo) = cls.members.isEmpty() && cls.vftable == null && cls.typeinfo == null &&
        cls.bases.isEmpty() && derivedOf(cls).isEmpty()

    companion object {
        fun of(program: Program): ClassHierarchy = Builder(program).build()
    }

    private class Builder(val program: Program) {
        val symtab: SymbolTable = program.symbolTable
        val record = ClassHierarchyRecord.read(program).orEmpty()
        val attrsAt = ClassHierarchyRecord.memberAttrs(program)
        val rtti = Rtti.Reader(program)

        // `_ZTI` objects by the class they describe, off the mangled label or, once Ghidra's demangler
        // ran, its `typeinfo` label in the class's namespace.
        val typeinfoByClass: Map<List<String>, Address> by lazy {
            buildMap {
                for (sym in symtab.getSymbolIterator(true)) {
                    if (!sym.isTypeinfo) continue
                    val cls = sym.typeinfoClass ?: continue
                    putIfAbsent(cls.nameSegments, sym.address)
                }
            }
        }

        fun build(): ClassHierarchy {
            val namespaces = linkedMapOf<Long, GhidraClass>()
            val typeinfos = mutableMapOf<Long, Address>()
            for (ns in classNamespaces()) {
                val typeinfo = typeinfoByClass[ns.getPathList(true).toList()]
                if (ns.id !in record && primaryVftableLabel(ns) == null && typeinfo == null) continue
                namespaces[ns.id] = ns
                typeinfo?.let { typeinfos[ns.id] = it }
            }
            val byPath = namespaces.values.associateBy { it.getPathList(true).toList() }
            val classes = namespaces.values.map { ns ->
                val vftableLabel = primaryVftableLabel(ns)
                val vftable = vftableLabel?.address
                val typeinfo = typeinfos[ns.id]
                val struct = structOf(ns)
                val vftableStruct = vftableStructOf(ns, vftableLabel)
                ClassInfo(
                    id = ns.id,
                    path = ns.getPathList(true).toList(),
                    origin = when {
                        ns.id in record -> Origin.STABS
                        typeinfo != null -> Origin.SWEPT_RTTI
                        else -> Origin.SWEPT
                    },
                    vftable = vftable?.toString(),
                    vftableStructId = vftableStruct?.let(program.dataTypeManager::getID)?.takeIf { it >= 0 },
                    typeinfo = typeinfo?.toString(),
                    structId = struct?.let(program.dataTypeManager::getID)?.takeIf { it >= 0 },
                    structName = struct?.name,
                    isAbstract = program.vftablesOf(ns).any(::hasPureVirtualSlot),
                    members = membersOf(ns),
                    bases = basesOf(ns, typeinfo, namespaces.keys) { path -> byPath[path]?.id },
                )
            }
            return ClassHierarchy(classes.sortedBy { it.qualifiedName })
        }

        fun basesOf(ns: GhidraClass, typeinfo: Address?, classIds: Set<Long>, idOf: (List<String>) -> Long?) =
            record[ns.id]?.bases?.map { base ->
                val target = base.namespaceId?.takeIf { it in classIds }
                val name = base.namespaceId?.let { (symtab.getSymbol(it)?.`object` as? Namespace)?.getName(true) }
                    ?: base.name ?: "?"
                BaseRef(name, target, base.isVirtual, base.access)
            } ?: typeinfo?.let(rtti::basesOf).orEmpty().map { base ->
                BaseRef(base.className, idOf(base.className.nameSegments), base.isVirtual, base.access)
            }

        fun classNamespaces(): Sequence<GhidraClass> = symtab.classNamespaces.asSequence()

        // The primary: `vftable` while the class has one table, else whichever `vftable_for_<Base>` it is.
        fun primaryVftableLabel(ns: Namespace): Symbol? = symtab.getSymbols(ns).iterator().asSequence()
            .filter { ClassNaming.isClassVftableLabel(it.name) }
            .firstOrNull { program.isPrimaryVftable(it) }

        // By the id the import recorded: typedef shortening may have renamed it, or it sits under a CU's
        // category (crypto_mi's `/dll.cpp/multi/ECP`), and Ghidra's lookup goes by name and scope.
        fun structOf(ns: GhidraClass): Structure? =
            record[ns.id]?.structId?.let(program.dataTypeManager::getDataType) as? Structure
                ?: VariableUtilities.findExistingClassStruct(ns, program.dataTypeManager)

        // Renamed once the class has several, so found off its label rather than by `<Class>_vftable`.
        fun vftableStructOf(ns: GhidraClass, label: Symbol?): Structure? = label?.let(program::vftableStructAt)
            ?: program.dataTypeManager.getDataType(ClassNaming.vftablePath(ns)) as? Structure

        fun membersOf(ns: Namespace): List<Member> {
            val virtuals by lazy { program.virtualsOf(ns) }
            val members = symtab.getSymbols(ns).mapNotNull { sym ->
                when (sym.symbolType) {
                    SymbolType.FUNCTION -> (sym.`object` as? Function)?.let { fn ->
                        val kind = if (fn.isThunk || fn.isThunkLinkage()) MemberKind.THUNK else MemberKind.FUNCTION
                        Member(
                            sym.name,
                            sym.address.toString(),
                            kind,
                            fn.getPrototypeString(false, false),
                            fn.params,
                            attrs = attrsAt(sym.address) ?: fn.derivedAttrs(virtuals),
                            variants = symtab.getSymbols(sym.address).mapNotNull { StructorVariant.of(it.name) }
                                .distinct().sorted(),
                        )
                    }

                    SymbolType.LABEL -> sym.labelKind().let { kind ->
                        val attrs = attrsAt(sym.address)
                            ?: MemberAttrs(virt = VirtKind.STATIC).takeIf { kind == MemberKind.LABEL }
                        Member(sym.name, sym.address.toString(), kind, attrs = attrs)
                    }

                    else -> null
                }
            }
            // gcc >= 3 emits a ctor or dtor once per variant (complete, base, deleting), and the stabs name
            // one; the others are the same member. Only these: `f()` and `f() const` share parameters.
            val structors = setOf(ns.name, "~${ns.name}")
            val stated = members.filter { it.name in structors && it.attrs?.access != null }
                .associateBy { it.name to it.parameters }
            val filled = members.map { m ->
                stated[m.name to m.parameters]?.takeIf { m.attrs?.access == null }?.let { m.copy(attrs = it.attrs) }
                    ?: m
            }
            val overloaded = filled.filter { it.parameters != null }.groupingBy { it.name }.eachCount()
                .filterValues { it > 1 }.keys
            return filled.map { if (it.name in overloaded) it.copy(isOverloaded = true) else it }
                .sortedWith(MEMBER_ORDER)
        }

        /**
         * With no signature yet (a swept class's functions, before the demangler analyzer applied one),
         * the parameters its mangled name declares, off the linkage label beside it.
         */
        val Function.params: String get() = (
            symtab.takeIf { signatureSource == SourceType.DEFAULT && parameterCount == 0 }
                ?.getSymbols(entryPoint)?.firstNotNullOfOrNull { Demangler.of(it.name) as? DemangledFunction }
                ?.parameters?.map { it.type }
                ?.filterNot { it.isVoid && it.pointerLevels == 0 && !it.isReference }
                ?.map { it.signature }
                ?: parameters.filterNot { it.isInjected || it.name == Gcc2.IN_CHARGE }.map { it.dataType.displayName }
            ).let { types -> (if (hasVarArgs()) types + "..." else types).joinToString(", ", "(", ")") }

        /** A this-adjusting thunk by its linkage name, gcc 2.x or Itanium. */
        fun Function.isThunkLinkage() = symtab.getSymbols(entryPoint).any { CxxAbi.looksLikeThunk(it.name) }

        /**
         * What the program shows of a member function the stabs don't describe: its cv-qualifiers off its
         * mangled name (Itanium `_ZNK…`/`_ZNV…`, gcc 2.x `__C…`), virtual when one of its class's vtables
         * holds it ([virtuals]). Neither says its access, nor static from plain.
         */
        fun Function.derivedAttrs(virtuals: Set<Address>): MemberAttrs {
            val demangled = symtab.getSymbols(entryPoint)
                .firstNotNullOfOrNull { Demangler.of(it.name) as? DemangledFunction }
            // Ghidra's GNU parser flags a trailing const but not volatile, so read both off the text.
            val qualifiers = demangled?.originalDemangled?.substringAfterLast(')').orEmpty().split(' ')
            return MemberAttrs(
                virt = VirtKind.VIRTUAL.takeIf { entryPoint in virtuals },
                isConst = "const" in qualifiers,
                isVolatile = "volatile" in qualifiers,
            )
        }

        /** A label's kind by its demangled name, else by the first mangled name at its address. */
        fun Symbol.labelKind(): MemberKind {
            val (abi, mangled) = (sequenceOf(this) + symtab.getSymbols(address).asSequence())
                .firstNotNullOfOrNull { CxxAbi.mangledBy(it.name)?.to(it.name) } ?: (null to name)
            val special = (abi as? Itanium)?.specialName(mangled)
            return when {
                name in VTABLE_LABELS || ClassNaming.isVftableLabel(name) || special == SpecialName.VTABLE ->
                    MemberKind.VTABLE

                name in ABI_LABELS || special != null -> MemberKind.ABI

                else -> MemberKind.LABEL
            }
        }

        fun hasPureVirtualSlot(vftable: Address): Boolean = program.slotTargets(vftable).any { target ->
            val name = program.functionManager.getFunctionAt(target)?.let { fn ->
                fn.getThunkedFunction(true)?.name ?: fn.name
            } ?: symtab.getPrimarySymbol(target)?.name
            name != null && name.trimStart('_') in PURE_VIRTUAL
        }
    }
}

/** Every function [ns]'s vtables hold, a thunk's target with it. */
private fun Program.virtualsOf(ns: Namespace): Set<Address> = buildSet {
    for (target in vftablesOf(ns).flatMap(::slotTargets)) {
        add(target)
        functionManager.getFunctionAt(target)?.getThunkedFunction(true)?.let { add(it.entryPoint) }
    }
}

/** Where each of [ns]'s vftables sits: the primary and every `internal_vftable`, or each `vftable_for_<Base>`. */
private fun Program.vftablesOf(ns: Namespace): Sequence<Address> = symbolTable.getSymbols(ns).iterator().asSequence()
    .filter { ClassNaming.isClassVftableLabel(it.name) }
    .map { it.address }

/**
 * Read off memory by the ABI's slot geometry rather than the laid struct's components: a gcc
 * 2.x slot is `{delta, index, pfn}`, and gcc 2.7's own stab types the pfn as a union a short
 * shows through. Only a gcc 2.x table carries its ABI's symbol at the label; an Itanium
 * `vftable` sits at the address point, past `_ZTV`.
 */
private fun Program.slotTargets(vftable: Address): Sequence<Address> {
    val length = listing.getDataAt(vftable)?.length ?: return emptySequence()
    val abi = symbolTable.getSymbols(vftable).firstNotNullOfOrNull { CxxAbi.ofVtableSymbol(it.name) } ?: Itanium
    val ptr = defaultPointerSize
    val stride = abi.stride(ptr)
    return (0 until length / stride).asSequence().mapNotNull { i ->
        runCatching { readPointer(vftable.add(i * stride + abi.pfnOffset(ptr))) }.getOrNull()
    }
}

private val PURE_VIRTUAL = setOf("cxa_pure_virtual", "pure_virtual")

// Vtables, then the other ABI objects, then functions and labels mixed by name, as the Symbol Tree.
private val MEMBER_ORDER = compareBy<ClassHierarchy.Member>(
    { minOf(it.kind, ClassHierarchy.MemberKind.FUNCTION) },
    { it.name },
    { it.parameters },
    { it.variants.firstOrNull() },
    { it.label },
    { it.address },
)

// The demangler's labels for Itanium special names, for when only those are left (the mangled names go
// through [Itanium.specialName]). A static data member (`_ZN…E`)
// stays a plain label.
private val VTABLE_LABELS = setOf(
    ClassNaming.vtableLabel(internal = false),
    ClassNaming.vtableLabel(internal = true),
    ClassNaming.vtableLabel(internal = true, construction = true),
    "VTT",
    "construction-vtable",
)
private val ABI_LABELS = setOf(ClassNaming.TYPEINFO, "typeinfo-name")
