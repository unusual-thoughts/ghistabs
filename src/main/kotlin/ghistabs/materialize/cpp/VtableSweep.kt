package ghistabs.materialize.cpp

import ghidra.app.util.demangler.DemangledDataType
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.symbol.Namespace
import ghistabs.Demangler
import ghistabs.materialize.cpp.abi.*
import ghistabs.parse.canonTemplateName
import ghistabs.parse.leafName
import ghistabs.parse.nameSegments

/**
 * Lay every `_ZTV…` symbol no harvested class claimed. `buildAndApplyVtable` runs per group, i.e.
 * only for a class we have a `T`-stab body for; libsupc++ and libstdc++ link without stabs, so
 * their polymorphic classes (`__cxxabiv1::__si_class_type_info`, `std::basic_filebuf<char,…>`)
 * own a real vtable that nothing ever visits — 53 of unbouniaf's 58 `_ZTV` symbols.
 *
 * Lossy by nature: with no method list the slots can only be named and typed from whatever sits
 * at the addresses they point to, and the array's length is inferred (see [vtableSlotTargets]).
 * The class struct is *not* synthesised — this is the vtable level only; §24 covers the same
 * classes at the typeinfo-record level.
 */
internal fun ClassApplier.sweepUnclaimedVtables() {
    val unclaimed = symtab.symbolIterator
        .filter { it.address !in claimedVtables }
        .mapNotNull { sym -> ResolvedVtable.fromSymbol(sym) }
        .distinctBy { it.address }
        .toList()

    monitor.initialize(unclaimed.size.toLong(), "Stabs: sweeping unclaimed vtables")
    for ((qualified, addr, abi) in unclaimed) {
        monitor.increment()
        val shape = program.vtableShape(addr, resolver, abi)
        val targets = program.vtableSlotTargets(shape.addressPoint, resolver, abi)
        if (targets.isEmpty()) {
            degradation("vtable-swept-empty", qualified, "no function pointers", shape.addressPoint)
            continue
        }
        val leaf = canonTemplateName(qualified.leafName)
        val category = CategoryPath(ClassNaming.classDataTypesRoot, leaf)
        val vftable = registry.getOrRegister<Structure>(category, "${leaf}_vftable") {
            StructureDataType(category, "${leaf}_vftable", 0, dtm)
        }
        // A class whose own group failed to resolve its vtable left its stab-typed slots here;
        // those beat anything read back off the target addresses.
        if (vftable.numComponents == 0) {
            val used = mutableSetOf<String>()
            with(abi) {
                vftable.addReservedHeader()
                targets.forEachIndexed { slot, target ->
                    vftable.addEntryAdjustment(slot)
                    addSweptSlot(vftable, category, target, used, abi)
                }
            }
        }

        val ns = buildNamespaceChain(qualified.nameSegments)
        val addressPoint = program.layVtable(shape, vftable, qualified, ns, resolver, abi = abi)
        debug("vtable-reconstructed", "${targets.size} slot(s) typed from targets", addressPoint, qualified)
        // Itanium packs a class's secondaries into the same record, walkable from the primary's
        // end by their shared rtti word. gcc 2.x gives each its own `_vt.<derived>.<base>`
        // symbol instead, so there is nothing contiguous to walk — and nothing claims them yet
        // either, since ResolvedVtable.fromSymbol screens the two-segment names out.
        if (abi.hasRttiHeader) laySecondaryVtables(shape, leaf, ns, abi)
    }
}

/**
 * Lay the sub-vtables that follow the primary record [primary] (§54). Slots are typed off their
 * targets like a swept table's: a secondary holds `_ZTv0_n…`/`_ZThn…` thunks, which are their own
 * symbols with their own names.
 *
 * Where the primary ends is read off memory, not off the vftable laid there — `CryptoPP::Base`
 * declares fewer virtuals than its table holds, which put the walk inside the function array.
 * Each sub-vtable gets its own `internal_<i>` category, or a thunk sharing its target's leaf name
 * forks a `.conflict` per slot (1874 on crypto_mi).
 */
internal fun ClassApplier.laySecondaryVtables(primary: VtableShape, leaf: String, ns: Namespace, abi: CxxAbi) {
    val rtti = program.readWord(primary.rttiHeader) ?: return
    val ptr = program.defaultPointerSize.toLong()
    val slots = program.vtableSlotTargets(primary.addressPoint, resolver).size
    val subs = program.secondaryVtables(primary.addressPoint.add(slots * ptr), rtti, resolver)
    subs.forEachIndexed { i, sub ->
        val category = CategoryPath(CategoryPath(ClassNaming.classDataTypesRoot, leaf), "internal_$i")
        val name = "${leaf}_vftable_internal_$i"
        val vftable = registry.getOrRegister<Structure>(category, name) {
            StructureDataType(category, name, 0, dtm)
        }
        if (vftable.numComponents == 0) {
            val used = mutableSetOf<String>()
            for (target in sub.targets) addSweptSlot(vftable, category, target, used, abi)
        }
        val at = program.layVtable(
            sub.shape,
            vftable,
            leaf,
            ns,
            resolver,
            label = ClassNaming.INTERNAL_VFTABLE,
        )
        debug("vtable-secondary", "class=$leaf index=$i slots=${sub.targets.size}", address = at)
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
internal fun ClassApplier.addSweptSlot(
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
    vftable.add(PointerDataType(registry.register(funcDef), dtm), name, "$target")
}

/** FunctionDefinition [name] carrying what [linkage] declares — the only type source for a slot
 *  target that has a linkage name and nothing else. Names but does not type an unmangled one. */
internal fun ClassApplier.demangledDefinition(category: CategoryPath, name: String, linkage: String) =
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
