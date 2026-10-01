package ghistabs.hierarchy

import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolType
import ghistabs.Demangler
import ghistabs.importer.ClassHierarchyRecord
import ghistabs.isInjected
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.CxxAbi
import ghistabs.materialize.cpp.abi.Itanium
import ghistabs.materialize.cpp.abi.RttiReader
import ghistabs.materialize.cpp.abi.isTypeinfo
import ghistabs.materialize.cpp.abi.typeinfoClass
import ghistabs.parse.Access
import ghistabs.parse.nameSegments
import ghistabs.readPointer

/**
 * Every class the program knows, with its direct bases, as the Class Hierarchy window shows them.
 *
 * Two sources, never mixed for one class: the stabs import's [ClassHierarchyRecord], exact down to
 * virtuality and access, gcc 2.x included; and, for a class the stabs never described but the vtable
 * sweep laid a `vftable` for, its Itanium typeinfo, when the program has one. A class with neither is
 * still listed, as a root, so the sweep's finds all show.
 */
class ClassHierarchy private constructor(val classes: List<ClassInfo>) {
    enum class Origin {
        /** Described by the stabs: the import recorded its bases. */
        STABS,

        /** Laid by the vtable sweep, bases read off its `_ZTI` typeinfo. */
        SWEPT_RTTI,

        /** Laid by the vtable sweep with no typeinfo to read: bases unknown. */
        SWEPT,
    }

    /** A direct base: the class it names, if the program has one for it, else only its [name]. */
    data class BaseRef(val name: String, val target: ClassInfo?, val isVirtual: Boolean, val access: Access?)

    /**
     * A function or label in the class's namespace, as the Symbol Tree lists it. An overloaded function
     * is spelled with its [parameters], `this` and the return type left out so overloads line up.
     */
    data class Member(
        val name: String,
        val address: Address,
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

    class ClassInfo(
        val namespace: GhidraClass,
        val origin: Origin,
        /** Where its primary `vftable` label sits, for a polymorphic class. */
        val vftable: Address?,
        /** Its `_ZTI` typeinfo object, when the binary has one. */
        val typeinfo: Address?,
        /** The struct the stabs laid for it, under the class's own name. */
        val struct: DataType?,
        /** A vftable slot holds `__cxa_pure_virtual` (gcc 2.x: `__pure_virtual`). */
        val isAbstract: Boolean,
        /** Its functions and labels: vtables first, then the other ABI objects, then the rest by name. */
        val members: List<Member>,
    ) {
        val path: List<String> = namespace.getPathList(true).toList()
        val name: String get() = namespace.name
        val qualifiedName: String get() = namespace.getName(true)

        var bases: List<BaseRef> = emptyList()
            internal set

        /** The classes that name this one as a direct base, each with that base clause. */
        var derived: List<Derived> = emptyList()
            internal set

        /** No base the program has a class for: a root of the inverted tree. */
        val isBasal: Boolean get() = bases.none { it.target != null }

        /** Where a double-click goes: the vtable, else the typeinfo. */
        val address: Address? get() = vftable ?: typeinfo

        override fun toString() = qualifiedName
    }

    val byNamespaceId: Map<Long, ClassInfo> = classes.associateBy { it.namespace.id }

    companion object {
        fun of(program: Program): ClassHierarchy = Builder(program).build()
    }

    private class Builder(val program: Program) {
        val symtab = program.symbolTable
        val record = ClassHierarchyRecord.read(program).orEmpty()
        val structIds = ClassHierarchyRecord.readStructs(program)
        val rtti = RttiReader(program)

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
            val infos = linkedMapOf<Long, ClassInfo>()
            for (ns in classNamespaces()) {
                val origin = when {
                    ns.id in record -> Origin.STABS
                    else -> null
                }
                val vftable = vftableOf(ns)
                val typeinfo = typeinfoByClass[ns.getPathList(true).toList()]
                if (origin == null && vftable == null && typeinfo == null) continue
                infos[ns.id] = ClassInfo(
                    ns,
                    origin ?: if (typeinfo != null) Origin.SWEPT_RTTI else Origin.SWEPT,
                    vftable,
                    typeinfo,
                    structOf(ns),
                    vftable?.let(::hasPureVirtualSlot) == true,
                    membersOf(ns),
                )
            }
            val byPath = infos.values.associateBy { it.path }
            for (info in infos.values) {
                info.bases = when (info.origin) {
                    Origin.STABS -> record.getValue(info.namespace.id).map { base ->
                        val target = base.namespaceId?.let { infos[it] }
                        val name = target?.qualifiedName
                            ?: base.namespaceId?.let { (symtab.getSymbol(it)?.`object` as? Namespace)?.getName(true) }
                            ?: base.name ?: "?"
                        BaseRef(name, target, base.isVirtual, base.access)
                    }

                    else -> info.typeinfo?.let(rtti::basesOf).orEmpty().map { base ->
                        BaseRef(base.className, byPath[base.className.nameSegments], base.isVirtual, base.access)
                    }
                }
            }
            linkDerived(infos.values)
            return ClassHierarchy(infos.values.sortedBy { it.qualifiedName })
        }

        fun linkDerived(infos: Collection<ClassInfo>) {
            val derived = infos.flatMap { info ->
                info.bases.mapNotNull { b -> b.target?.let { it to Derived(info, b) } }
            }
                .groupBy({ it.first }, { it.second })
            for ((base, list) in derived) base.derived = list.sortedBy { it.cls.qualifiedName }
        }

        fun classNamespaces(): Sequence<GhidraClass> = symtab.classNamespaces.asSequence()

        fun vftableOf(ns: Namespace): Address? = symtab.getSymbols(ClassNaming.VFTABLE, ns).firstOrNull()?.address

        // By the id the import recorded, since typedef shortening may have renamed it; else by name.
        fun structOf(ns: GhidraClass): DataType? = structIds[ns.id]?.let(program.dataTypeManager::getDataType)
            ?: ns.getPathList(true).toList().let { path ->
                val scope = path.dropLast(1)
                val category = if (scope.isEmpty()) CategoryPath.ROOT else CategoryPath(CategoryPath.ROOT, scope)
                program.dataTypeManager.getDataType(category, path.last()) as? Structure
            }

        fun membersOf(ns: Namespace): List<Member> {
            val members = symtab.getSymbols(ns).mapNotNull { sym ->
                when (sym.symbolType) {
                    SymbolType.FUNCTION -> (sym.`object` as? Function)?.let { fn ->
                        val kind = if (fn.isThunk) MemberKind.THUNK else MemberKind.FUNCTION
                        Member(sym.name, sym.address, kind, fn.getPrototypeString(false, false), parametersOf(fn))
                    }

                    SymbolType.LABEL -> Member(sym.name, sym.address, labelKind(sym))

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
        fun parametersOf(fn: Function): String {
            val types = if (fn.signatureSource == SourceType.DEFAULT && fn.parameterCount == 0) {
                symtab.getSymbols(fn.entryPoint).firstNotNullOfOrNull { Demangler.of(it.name) as? DemangledFunction }
                    ?.parameters?.map { it.type }?.filterNot { it.isVoid && it.pointerLevels == 0 && !it.isReference }
                    ?.map { it.signature }
            } else {
                null
            } ?: fn.parameters.filterNot { it.isInjected }.map { it.dataType.displayName }
            return (if (fn.hasVarArgs()) types + "..." else types).joinToString(", ", "(", ")")
        }

        fun labelKind(sym: Symbol): MemberKind {
            val mangled = (sequenceOf(sym) + symtab.getSymbols(sym.address).asSequence())
                .map { it.name }.firstOrNull { it.startsWith("_Z") }.orEmpty()
            return when {
                sym.name in VTABLE_LABELS || VTABLE_MANGLED.any(mangled::startsWith) -> MemberKind.VTABLE
                sym.name in ABI_LABELS || ABI_MANGLED.any(mangled::startsWith) -> MemberKind.ABI
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

// The demangler's labels for Itanium special names, and those names' mangled prefixes: `_ZTV` vtable,
// `_ZTT` VTT, `_ZTC` construction vtable; `_ZTI` typeinfo, `_ZTS` its name, `_ZG*` guard variables
// and reference temporaries. A static data member (`_ZN…E`) stays a plain label.
private val VTABLE_LABELS = setOf(
    ClassNaming.VFTABLE,
    ClassNaming.INTERNAL_VFTABLE,
    Itanium.DEMANGLED_VTABLE,
    "VTT",
    "construction-vtable",
)
private val ABI_LABELS = setOf(Itanium.DEMANGLED_TYPEINFO, "typeinfo-name")
private val VTABLE_MANGLED = listOf("_ZTV", "_ZTT", "_ZTC")
private val ABI_MANGLED = listOf("_ZT", "_ZG")
