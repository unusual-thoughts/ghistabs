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
import ghistabs.isInjected
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.*
import ghistabs.parse.Access
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
     * is spelled with its [parameters], `this` and the return type left out so overloads line up.
     */
    @Serializable
    data class Member(
        val name: String,
        val address: String,
        val kind: MemberKind,
        val signature: String? = null,
        val parameters: String? = null,
        val isOverloaded: Boolean = false,
    ) {
        val label: String get() = if (isOverloaded && parameters != null) name + parameters else name
    }

    enum class MemberKind {
        /** A vtable: our `vftable` / `internal_vftable`, or the demangler's `vtable`, `VTT`, `construction-vtable`. */
        VTABLE,

        /** Any other Itanium special name (`_ZT*`, `_ZG*`): `typeinfo`, `typeinfo-name`, guard variables. */
        ABI,
        FUNCTION,
        THUNK,
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
        /** A vftable slot holds `__cxa_pure_virtual` (gcc 2.x: `__pure_virtual`). */
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

    companion object {
        fun of(program: Program): ClassHierarchy = Builder(program).build()
    }

    private class Builder(val program: Program) {
        val symtab: SymbolTable = program.symbolTable
        val record = ClassHierarchyRecord.read(program).orEmpty()
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
                if (ns.id !in record && vftableOf(ns) == null && typeinfo == null) continue
                namespaces[ns.id] = ns
                typeinfo?.let { typeinfos[ns.id] = it }
            }
            val byPath = namespaces.values.associateBy { it.getPathList(true).toList() }
            val classes = namespaces.values.map { ns ->
                val vftable = vftableOf(ns)
                val typeinfo = typeinfos[ns.id]
                val struct = structOf(ns)
                val vftableStruct = vftableStructOf(ns)
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
                    isAbstract = vftable?.let(::hasPureVirtualSlot) == true,
                    members = membersOf(ns),
                    bases = basesOf(ns, typeinfo, namespaces.keys) { path -> byPath[path]?.id },
                )
            }
            return ClassHierarchy(classes.sortedBy { it.qualifiedName })
        }

        fun basesOf(ns: GhidraClass, typeinfo: Address?, classIds: Set<Long>, idOf: (List<String>) -> Long?) =
            record[ns.id]?.map { base ->
                val target = base.namespaceId?.takeIf { it in classIds }
                val name = base.namespaceId?.let { (symtab.getSymbol(it)?.`object` as? Namespace)?.getName(true) }
                    ?: base.name ?: "?"
                BaseRef(name, target, base.isVirtual, base.access)
            } ?: typeinfo?.let(rtti::basesOf).orEmpty().map { base ->
                BaseRef(base.className, idOf(base.className.nameSegments), base.isVirtual, base.access)
            }

        fun classNamespaces(): Sequence<GhidraClass> = symtab.classNamespaces.asSequence()

        fun vftableOf(ns: Namespace): Address? = symtab.getSymbols(ClassNaming.VFTABLE, ns).firstOrNull()?.address

        // By the id the import recorded, since typedef shortening may have renamed it; else by name.
        fun structOf(ns: GhidraClass): Structure? =
            VariableUtilities.findExistingClassStruct(ns, program.dataTypeManager)

        fun vftableStructOf(ns: GhidraClass): Structure? =
            program.dataTypeManager.getDataType(ClassNaming.vftablePath(ns)) as? Structure

        fun membersOf(ns: Namespace): List<Member> {
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
                        )
                    }

                    SymbolType.LABEL -> Member(sym.name, sym.address.toString(), sym.labelKind())

                    else -> null
                }
            }
            val overloaded = members.filter { it.parameters != null }.groupingBy { it.name }.eachCount()
                .filterValues { it > 1 }.keys
            return members.map { if (it.name in overloaded) it.copy(isOverloaded = true) else it }
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

        /** A label's kind by its demangled name, else by the first Itanium-mangled name at its address. */
        fun Symbol.labelKind(): MemberKind {
            val mangled = (sequenceOf(this) + symtab.getSymbols(address).asSequence())
                .map { it.name }.firstOrNull(Itanium::isProbablyMangled).orEmpty()
            val special = Itanium.specialName(mangled)
            return when {
                name in VTABLE_LABELS || special == SpecialName.VTABLE -> MemberKind.VTABLE
                name in ABI_LABELS || special != null -> MemberKind.ABI
                else -> MemberKind.LABEL
            }
        }

        fun hasPureVirtualSlot(vftable: Address): Boolean = slotTargets(vftable).any { target ->
            val name = program.functionManager.getFunctionAt(target)?.let { fn ->
                fn.getThunkedFunction(true)?.name ?: fn.name
            } ?: symtab.getPrimarySymbol(target)?.name
            name != null && name.trimStart('_') in PURE_VIRTUAL
        }

        /**
         * Read off memory by the ABI's slot geometry rather than the laid struct's components: a gcc
         * 2.x slot is `{delta, index, pfn}`, and gcc 2.7's own stab types the pfn as a union a short
         * shows through. Only a gcc 2.x table carries its ABI's symbol at the label; an Itanium
         * `vftable` sits at the address point, past `_ZTV`.
         */
        fun slotTargets(vftable: Address): Sequence<Address> {
            val length = program.listing.getDataAt(vftable)?.length ?: return emptySequence()
            val abi = symtab.getSymbols(vftable).firstNotNullOfOrNull { CxxAbi.ofVtableSymbol(it.name) } ?: Itanium
            val ptr = program.defaultPointerSize
            val stride = abi.stride(ptr)
            return (0 until length / stride).asSequence().mapNotNull { i ->
                runCatching { program.readPointer(vftable.add(i * stride + abi.pfnOffset(ptr))) }.getOrNull()
            }
        }
    }
}

private val PURE_VIRTUAL = setOf("cxa_pure_virtual", "pure_virtual")

// Vtables, then the other ABI objects, then functions and labels mixed by name, as the Symbol Tree.
private val MEMBER_ORDER = compareBy<ClassHierarchy.Member>(
    { minOf(it.kind, ClassHierarchy.MemberKind.FUNCTION) },
    { it.name },
    { it.label },
    { it.address },
)

// The demangler's labels for Itanium special names, for when only those are left (the mangled names go
// through [Itanium.specialName]). A static data member (`_ZN…E`)
// stays a plain label.
private val VTABLE_LABELS = setOf(
    ClassNaming.VFTABLE,
    ClassNaming.INTERNAL_VFTABLE,
    Itanium.DEMANGLED_VTABLE,
    "VTT",
    "construction-vtable",
)
private val ABI_LABELS = setOf(Itanium.DEMANGLED_TYPEINFO, "typeinfo-name")
