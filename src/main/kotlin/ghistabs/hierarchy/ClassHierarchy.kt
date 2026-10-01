package ghistabs.hierarchy

import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghistabs.importer.ClassHierarchyRecord
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.CxxAbi
import ghistabs.materialize.cpp.abi.Itanium
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
    ) {
        val path: List<String> = namespace.getPathList(true).toList()
        val name: String get() = namespace.name
        val qualifiedName: String get() = namespace.getName(true)

        var bases: List<BaseRef> = emptyList()
            internal set

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
        val rtti = ItaniumTypeinfo(program)

        // `_ZTI` objects by the class they describe, off the mangled label: the demangler's `typeinfo`
        // label in the class's namespace only exists once Ghidra's demangler has run.
        val typeinfoByClass: Map<List<String>, Address> by lazy {
            buildMap {
                for (sym in symtab.getSymbolIterator(true)) {
                    if (!Itanium.looksLikeZti(sym.name)) continue
                    val cls = Itanium.typeinfoClassOf(sym.name) ?: continue
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
            return ClassHierarchy(infos.values.sortedBy { it.qualifiedName })
        }

        fun classNamespaces(): Sequence<GhidraClass> = symtab.classNamespaces.asSequence()

        fun vftableOf(ns: Namespace): Address? = symtab.getSymbols(ClassNaming.VFTABLE, ns).firstOrNull()?.address

        fun structOf(ns: GhidraClass): DataType? = ns.getPathList(true).toList().let { path ->
            val scope = path.dropLast(1)
            val category = if (scope.isEmpty()) CategoryPath.ROOT else CategoryPath(CategoryPath.ROOT, scope)
            program.dataTypeManager.getDataType(category, path.last()) as? Structure
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
