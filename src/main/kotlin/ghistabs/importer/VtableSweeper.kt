package ghistabs.importer

import ghidra.app.util.demangler.DemangledDataType
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.BoolOption
import ghistabs.Demangler
import ghistabs.at
import ghistabs.buildClassNamespaces
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.get
import ghistabs.materialize.DtmRegistry
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.*
import ghistabs.materialize.cpp.describeVxTable
import ghistabs.materialize.cpp.vfptrOffsetOfBase
import ghistabs.parse.canonTemplateName
import ghistabs.parse.leafName
import ghistabs.parse.nameSegments
import ghistabs.readPointer
import ghistabs.set

/** One gcc 2.x secondary vtable record: its symbol's [base] and ABI, and where it sits. */
internal data class Gcc2SecondaryVtable(val base: String, val address: Address, val abi: CxxAbi)

/**
 * Lays the vtables of classes nothing describes: every `_ZTV…` (and gcc 2.x `_vt…`) symbol whose record
 * no class has claimed ([isVtableClaimed]), typed off whatever sits at the addresses its slots hold.
 * Needs only the symbol table and memory: [ghistabs.entrypoints.GccVftableAnalyzer] runs the sweep,
 * on a binary with no stabs at all as much as after a stabs import. [ClassApplier] extends it only for
 * the table-laying helpers, which it uses on the classes the stabs describe, and never sweeps.
 */
open class VtableSweeper(
    internal open val registry: DtmRegistry,
    internal val program: Program,
    internal val monitor: TaskMonitor,
    private val sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    internal val symtab = program.symbolTable
    internal val dtm = program.dataTypeManager

    companion object {
        /** What a swept table's labels carry, so a class laying it later claims it ([isVtableClaimed]). */
        private val SWEPT = SourceType.ANALYSIS

        val VTABLES_SWEPT = BoolOption("Vtables Swept", "Unclaimed vtables already swept.", false)

        /** Whether a sweep already ran here: the stabs import's, or [ghistabs.entrypoints.GccVftableAnalyzer]'s. */
        val Program.isVtablesSwept get() = this[VTABLES_SWEPT]

        fun Program.markVtablesSwept() {
            this[VTABLES_SWEPT] = true
        }
    }

    /**
     * gcc 2.x secondary vtables (`_vt.<class>.<base>`) by the qualified class they belong to, one per
     * record in address order: a.out keeps both `_vt$` and its user-label-prefixed `__vt$` at one
     * address. Empty for any other ABI.
     */
    private val gcc2SecondaryVtables: Map<String, List<Gcc2SecondaryVtable>> by lazy {
        buildMap {
            for (sym in symtab.symbolIterator) {
                val (cls, base) = Gcc2.secondaryVtableClasses(sym.name) ?: continue
                val abi = CxxAbi.ofVtableSymbol(sym.name) ?: continue
                getOrPut(cls) { mutableListOf() } += Gcc2SecondaryVtable(base, sym.address, abi)
            }
        }.mapValues { (_, tables) -> tables.distinctBy { it.address }.sortedBy { it.address } }
    }

    /**
     * Lay every `_ZTV…` symbol no class claimed. `buildAndApplyVtable` runs per group, i.e.
     * only for a class we have a `T`-stab body for; libsupc++ and libstdc++ link without stabs, so
     * their polymorphic classes (`__cxxabiv1::__si_class_type_info`, `std::basic_filebuf<char,…>`)
     * own a real vtable that nothing ever visits — 53 of unbouniaf's 58 `_ZTV` symbols.
     *
     * Lossy by nature: with no method list the slots can only be named and typed from whatever sits
     * at the addresses they point to, and the array's length is inferred (see [vtableSlotTargets]).
     * The class struct is *not* synthesised — this is the vtable level only; §24 covers the same
     * classes at the typeinfo-record level.
     *
     * Returns the number of primary vtables laid, and marks the program [isVtablesSwept].
     */
    internal fun sweepUnclaimedVtables(): Int {
        val unclaimed = symtab.symbolIterator
            .mapNotNull { sym -> ResolvedVtable.fromSymbol(sym) }
            .distinctBy { it.address }
            .filterNot { (_, addr, abi) -> program.isVtableClaimed(program.vtableShape(addr, abi), abi) }
            .toList()

        monitor.initialize(unclaimed.size.toLong(), "Sweeping unclaimed vtables")
        var laid = 0
        for ((qualified, addr, abi) in unclaimed) {
            monitor.increment()
            val shape = program.vtableShape(addr, abi)
            val targets = program.vtableSlotTargets(shape.addressPoint, abi)
            if (targets.isEmpty()) {
                degradation("vtable-swept-empty", qualified, "no function pointers", shape.addressPoint)
                continue
            }
            val leaf = canonTemplateName(qualified.leafName)
            val ns = symtab.buildClassNamespaces(qualified.nameSegments)
            val path = ClassNaming.vftableCategory(ns).at(leaf)
            val vftable = registry.getOrRegister<Structure>(path) {
                StructureDataType(path.categoryPath, path.dataTypeName, 0, dtm)
            }
            // A class whose own group failed to resolve its vtable left its stab-typed slots here;
            // those beat anything read back off the target addresses.
            if (vftable.numComponents == 0) {
                addSweptSlots(vftable, path.categoryPath, targets, abi)
                // Itanium puts a primary vptr at 0. gcc 2.x puts it after the fields, and with no class
                // struct here to read that off, it gets no tag.
                vftable.describeVxTable(leaf, ClassNaming.VFTABLE, 0L.takeIf { abi.hasRttiHeader })
            }

            val addressPoint = program.layVtable(shape, vftable, qualified, ns, abi = abi, source = SWEPT)
            debug("vtable-reconstructed", "${targets.size} slot(s) typed from targets", addressPoint, qualified)
            laid++
            // Itanium packs a class's secondaries into the same record, walkable from the primary's
            // end by their shared rtti word. gcc 2.x gives each its own `_vt.<derived>.<base>` symbol,
            // laid below whether or not the class has a primary at all.
            if (abi.hasRttiHeader) laySecondaryVtables(shape, leaf, ns, abi, SWEPT)
        }
        // What the class pass left: gcc 2.x secondaries of classes linked without stabs. No class struct
        // to find the base's vptr in, so these go untagged.
        for (cls in gcc2SecondaryVtables.keys) {
            layGcc2SecondaryVtables(
                cls,
                canonTemplateName(cls.leafName),
                symtab.buildClassNamespaces(cls.nameSegments),
                null,
                SWEPT,
            )
        }
        program.markVtablesSwept()
        return laid
    }

    /**
     * Lay the sub-vtables that follow the primary record [primary] (§54). A secondary holds
     * `_ZTv0_n…`/`_ZThn…` thunks, which are their own symbols with their own names.
     *
     * Where the primary ends is read off memory, not off the vftable laid there — `CryptoPP::Base`
     * declares fewer virtuals than its table holds, which put the walk inside the function array.
     */
    internal fun laySecondaryVtables(
        primary: VtableShape,
        leaf: String,
        ns: Namespace,
        abi: CxxAbi,
        source: SourceType = SourceType.IMPORTED,
    ) {
        val rtti = program.readPointer(primary.rttiHeader) ?: return
        val ptr = program.defaultPointerSize.toLong()
        val slots = program.vtableSlotTargets(primary.addressPoint).size
        // Only a record with slots is laid: an empty one has no function array to put a struct over.
        // Numbered over the laid ones, so a table behind an empty record keeps the name it always had.
        val subs = program.secondaryVtables(primary.addressPoint.add(slots * ptr), rtti)
            .filter { it.targets.isNotEmpty() }
        subs.forEachIndexed { i, sub ->
            val vftable = internalVftable(ClassNaming.vftablePath(ns), i, sub.targets, abi)
            val vfptrAt = with(abi) { sub.shape.vfptrOffset(program) }
            vftable.describeVxTable(leaf, "${ClassNaming.INTERNAL_VFTABLE} $i", vfptrAt)
            val at = program.layVtable(
                sub.shape,
                vftable,
                leaf,
                ns,
                label = ClassNaming.INTERNAL_VFTABLE,
                abi = abi,
                source = source,
            )
            debug("vtable-secondary", "class=$leaf index=$i slots=${sub.targets.size}", address = at)
        }
    }

    /**
     * [className]'s gcc 2.x secondaries, which are not packed behind a primary: each is its own record
     * under its own symbol, `_vt<m><class><m><base>` — `_vt$9TeeStream$3ios`, the table TeeStream's
     * virtual `ios` base points at. A class whose polymorphic bases are all virtual has no primary at
     * all, only these. The `internal_vftable` label goes at the record start, which is what a gcc 2.x
     * vptr holds.
     *
     * Tagged at that base's vptr in [classStruct], when there is one to look in: the vptr the table is
     * for belongs to the base, wherever the class lays it. A record a class already laid is skipped.
     */
    internal fun layGcc2SecondaryVtables(
        className: String,
        leaf: String,
        ns: Namespace,
        classStruct: Structure?,
        source: SourceType = SourceType.IMPORTED,
    ) {
        var laid = 0
        for ((base, at, abi) in gcc2SecondaryVtables[className].orEmpty()) {
            val shape = program.vtableShape(at, abi)
            if (program.isVtableClaimed(shape, abi)) continue
            val targets = program.vtableSlotTargets(shape.addressPoint, abi)
            if (targets.isEmpty()) {
                debug("vtable-secondary-empty", "class=$className base=$base", address = at)
                continue
            }
            val i = laid++
            val vftable = internalVftable(ClassNaming.vftablePath(ns), i, targets, abi)
            val vfptrAt = classStruct?.vfptrOffsetOfBase(base)?.toLong()
            vftable.describeVxTable(leaf, "${ClassNaming.INTERNAL_VFTABLE} $i, for $base", vfptrAt)
            program.layVtable(
                shape,
                vftable,
                leaf,
                ns,
                label = ClassNaming.INTERNAL_VFTABLE,
                abi = abi,
                source = source,
            )
            debug("vtable-secondary", "class=$className index=$i base=$base slots=${targets.size}", address = at)
        }
    }

    /**
     * [leaf]'s secondary [i], `<leaf>_vftable_internal_<i>`, typed off its [targets] like a swept table.
     * The table sits beside the primary in [ns]'s category, where shift-D finds the class it belongs
     * to. Its slot definitions each get their own `internal_<i>` category, or a thunk sharing its
     * target's leaf name forks a `.conflict` per slot (1874 on crypto_mi).
     */
    private fun internalVftable(path:DataTypePath, i: Int, targets: List<Address>, abi: CxxAbi): Structure {
        val name = "${path.dataTypeName}_vftable_internal_$i"
        val vftable = registry.getOrRegister<Structure>(path.categoryPath.at(name)) {
            StructureDataType(path.categoryPath, name, 0, dtm)
        }
        if (vftable.numComponents == 0) addSweptSlots(vftable, CategoryPath(path.categoryPath, "internal_$i"), targets, abi)
        return vftable
    }

    /** Fill [vftable] off [targets] alone: [abi]'s reserved header, then each slot with its adjustment. */
    private fun addSweptSlots(vftable: Structure, category: CategoryPath, targets: List<Address>, abi: CxxAbi) {
        val used = mutableSetOf<String>()
        with(abi) {
            vftable.addReservedHeader()
            targets.forEachIndexed { slot, target ->
                vftable.addEntryAdjustment(slot)
                addSweptSlot(vftable, category, target, used, abi)
            }
        }
    }

    /**
     * Add the swept slot pointing at [target]. Always `Pointer→FunctionDefinition`, never a bare
     * `void*`: an abstract class's slots point at `__cxa_pure_virtual`, a real function that honestly
     * has no signature to recover, and a `void*` there reads as a failure to type it.
     *
     * One name serves as both the field name and the definition's — `atLeastOneVtableStructApplied`
     * requires they agree (RecoveredClassHelper / shift-S round-trip) — so it has to be unique in the
     * category too: `std::num_get` has six `do_get` overloads and `std::ctype` two of each `do_is`/
     * `do_widen`/…, and one name across all of them forks a `.conflict` per slot (32 on unbouniaf).
     * [used] carries the names already spent on this table.
     */
    internal fun addSweptSlot(
        vftable: Structure,
        category: CategoryPath,
        target: Address,
        used: MutableSet<String>,
        abi: CxxAbi,
    ) {
        val linkage = symtab.getSymbols(target).map { it.name }.firstOrNull(abi::isProbablyMangled)
            ?: symtab.getPrimarySymbol(target)?.name
            ?: "slot"
        val leaf = Demangler.of(linkage)?.name ?: linkage
        val name = generateSequence(0) { it + 1 }
            .map { if (it == 0) leaf else "${leaf}_$it" }
            .first(used::add)

        val funcDef = program.functionManager.getFunctionAt(target)
            ?.let { FunctionDefinitionDataType(category, name, it.signature, dtm) }
            ?: demangledDefinition(category, name, linkage)
        vftable.add(PointerDataType(registry.registerAgain(funcDef), dtm), name, "$target")
    }

    /** FunctionDefinition [name] carrying what [linkage] declares — the only type source for a slot
     *  target that has a linkage name and nothing else. Names but does not type an unmangled one. */
    private fun demangledDefinition(category: CategoryPath, name: String, linkage: String) =
        FunctionDefinitionDataType(category, name, dtm).apply {
            fun DemangledDataType.dt() = runCatching { getDataType(dtm) }.getOrNull()
                ?: Undefined4DataType.dataType.also {
                    degradation("vftable-demangled-untyped", "$category/$name", "demangler gave no type for $this")
                }
            (Demangler.of(linkage) as? DemangledFunction)?.let { df ->
                df.returnType?.let { returnType = it.dt() }
                setArguments(
                    *df.parameters
                        .filterNot { it.type.isVoid && it.type.pointerLevels == 0 && !it.type.isReference }
                        .mapIndexed { i, p -> ParameterDefinitionImpl("arg$i", p.type.dt(), null) }
                        .toTypedArray(),
                )
            }
        }
}
