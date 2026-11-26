package ghicpp.recover

import ghicpp.*
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghicpp.MemberAttrs.Companion.recordPlaced
import ghicpp.StructorRole.CONSTRUCTOR
import ghicpp.StructorRole.DESTRUCTOR
import ghicpp.abi.generic.PlainClass
import ghicpp.abi.generic.PlainVtables
import ghicpp.dissect.*
import ghicpp.recover.MemberObjectPass.Companion.MAX_DEPTH
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink

/**
 * The classes with no vtable that the classes a class pass found hold as members. What a constructor calls first
 * on `this` + k, k past 0, is the constructor of the member there, and what a destructor calls last there its
 * destructor, where neither stores a vptr, as [FoundStructors.roles]' do. The structors one class's structors
 * call at one offset build and destroy one class, and so does any sharing one of them: the class one of them is
 * named in already, else `NPKlass_<address>` ([NON_POLYMORPHIC_PREFIX]) after its first constructor: the address
 * is that function's, as it has no vtable, where a `Klass_<address>` [GenericVftableFinder] seeds is its table's.
 * Its struct says so in its description. It is sized and filled off what
 * its constructors store, and laid in each class holding it at its offset. Its own members follow, down to
 * [MAX_DEPTH].
 *
 * So does an object `operator new` allocates whose constructor stores no vptr: the first function called on what
 * it returns, where that's no structor the class pass found, builds a class at least as large as allocated.
 *
 * A call at `this` + 0 builds a base, which the class pass reads. So does one a constructor of a class with no
 * vtable makes to another's constructor, or a destructor's last to another's destructor: that class is its base
 * at 0. Where the call is to a polymorphic class's constructor, that class is a member at 0, as a class deriving
 * from it would store a vptr of its own. Any other function a constructor calls on `this` + 0 sets up its fields
 * ([MemberObjects.helperStores]), so what it stores is the class's too. An ordinary method a constructor calls
 * first on a member with no constructor of its own looks the same as one, so this is a guess, as the pass's are.
 */
class MemberObjectPass(
    private val program: Program,
    sink: DiagnosticSink,
    /** Whether a field a constructor fills in a counted loop or with `memset` is an array ([ThisFunctionDissector]). */
    private val fillArrays: Boolean = true,
    /** Whether the objects `operator new` allocates get classes too, where their constructors store no vptr. */
    private val allocations: Boolean = true,
) : DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val thisStorage = program.thisStorage()

    /** What a subobject is, or is in: a class the class pass found, or a [NonPolymorphicClass] this pass drafts. */
    private sealed interface ContainingClass {
        /** Its class, where it has one. */
        val decl: ClassDecl?

        /** A class the class pass found. */
        data class Existing(val cls: ClassDecl) : ContainingClass {
            override val decl get() = cls
        }
    }

    /**
     * A class with no vtable, known only from its structors: those a found class's structors call on `this` + k,
     * what its constructors store, and the class it's given. Two that share a structor are one: the later is
     * [absorb]ed into the earlier, and stands for it ([merged]) from then on.
     */
    private class NonPolymorphicClass : ContainingClass {
        val ctors = linkedSetOf<Function>()
        val dtors = linkedSetOf<Function>()
        var stores: Stores = emptyMap()
        var cls: PlainClass? = null

        /** What each of its structors calls on `this` + k, by k. */
        val calls = mutableMapOf<Function, Map<Long, Set<Function>>>()

        /** The size `operator new` allocates it with, the largest; 0 where nothing allocates it. */
        var allocated = 0L

        /** The structor this pass named [cls] after, and its role, where nothing named it already. */
        var namedAfter: Pair<Function, StructorRole>? = null
        val functions get() = ctors + dtors

        val namedClass get() = functions.firstNotNullOfOrNull { f ->
            (f.parentNamespace as? GhidraClass)?.takeIf { f.symbol.source != SourceType.DEFAULT }
        }

        private var into: NonPolymorphicClass? = null

        /** The class this one is, after the merges: itself, or the one it was absorbed into. */
        val merged: NonPolymorphicClass get() = into?.merged ?: this

        override val decl get() = merged.cls

        /** Makes [other] one with this, which takes its structors. */
        fun absorb(other: NonPolymorphicClass) {
            if (other === this) return
            other.into = this
            ctors += other.ctors
            dtors += other.dtors
            allocated = maxOf(allocated, other.allocated)
        }
    }

    /**
     * A constructor or destructor of [container], as [role], and what it [calls] on `this` + k by k: [function],
     * or none for a constructor inlined after `operator new`.
     */
    private data class Structor(
        val function: Function?,
        val container: ContainingClass,
        val role: StructorRole,
        val calls: Map<Long, Set<Function>>? = null,
    )

    /** The subobject at [offset] in [container]. */
    private data class Subobject(val container: ContainingClass, val offset: Long)

    /**
     * Recovers the classes of the member objects of [found]'s classes, and with [allocations] those of the objects
     * `operator new` allocates whose constructor stores no vptr ([MemberObjects.allocated]), and returns how many it
     * made or found again.
     */
    fun run(found: FoundStructors, monitor: TaskMonitor = TaskMonitor.DUMMY): Int {
        val objects = MemberObjects(found, monitor)
        for (m in objects.drafts) m.buildClass()
        val byFunction = objects.drafts.flatMap { m -> m.functions.map { it to m } }.toMap()
        val atZero = mutableListOf<Pair<Subobject, ContainingClass>>()
        val bases = addNonPolymorphicBases(objects.drafts, byFunction, found, atZero)
        objects.helperStores(byFunction)
        val derived = addEmptyBases(objects.emptyBases.mapValues { (_, bases) -> bases.map { it.merged } })
        val classes = objects.drafts.filter { it.cls != null }
        val sizes = objects.sizes(classes, bases)
        monitor.initialize(classes.size.toLong(), "Naming member object classes' constructors and destructors")
        for (m in classes) {
            monitor.increment()
            val ns = m.cls?.ns?.toClass() ?: continue
            // Its struct first, so its structors' `this` is typed with it, not a placeholder of Ghidra's.
            runCatching { program.stubClassStruct(ns) }.onFailure {
                warn("member-struct-unstubbed", "${ns.qualifiedName}: $it")
            }
            val size = sizes[m] ?: 0
            runCatching { program.sizeClassStruct(ns, size) }.onFailure {
                warn("member-struct-unsized", "${ns.qualifiedName} -> $size: $it")
            }
            m.ctors.forEach { it.name(ns, CONSTRUCTOR) }
            m.dtors.forEach { it.name(ns, DESTRUCTOR) }
            m.namedAfter?.let { (f, role) -> describe(ns, f, role) }
        }
        val plainClasses = classes.mapNotNull { it.cls }
        monitor.message = "Filling member object class structs"
        ClassStructFiller(program, PlainVtables, this).fillAll(
            plainClasses,
            classes.associate { it.cls!! to it.stores },
        )
        // A polymorphic class at 0 is whole already: it goes in first.
        val laid = atZero + objects.subobjects
        monitor.initialize(laid.size.toLong(), "Laying member objects in their classes")
        for ((sub, what) in laid) {
            monitor.increment()
            val member = what.decl?.let(::structOf)?.takeUnless { it.isZeroLength } ?: continue
            val holder = sub.container.decl?.let(::structOf) ?: continue
            val at = sub.offset.toInt()
            // A base subobject the class pass laid there, a virtual one too, which the constructors build alike.
            if (holder.definedComponents.none { it.offset == at && it.dataType == member }) {
                placeMember(holder, at, member)
            }
        }
        val built = addFlaggedBases(objects.flaggedBases())
        // The members grew the classes they went past the end of, and with them those deriving from them.
        dtm.growToHoldBases(classStructs())
        writeRecords((plainClasses + derived + built).distinct())
        return classes.size
    }

    /**
     * The member objects of [found]'s classes and, with [allocations], the objects `operator new` allocates, read
     * off their structors, a level deeper each time, down to [MAX_DEPTH]: where each is and what ([subobjects]),
     * and the classes with no vtable drafted for them ([drafts]).
     */
    private inner class MemberObjects(private val found: FoundStructors, private val monitor: TaskMonitor) {
        /** One for the pass, so that each function is decompiled once, the allocations' callers' and structors'. */
        private val dissector = ThisFunctionDissector(
            program,
            emptyList(),
            this@MemberObjectPass,
            DissectionCache(fillArrays, operatorNewNames = PlainVtables.operatorNewNames),
        )

        /** The class drafted for each structor read, as first drafted: [NonPolymorphicClass.merged] since, maybe. */
        private val drafted = mutableMapOf<Function, NonPolymorphicClass>()

        /** What is at each subobject, a level each: the first in [found]'s classes and the allocated objects. */
        private val levels = mutableListOf<MutableMap<Subobject, ContainingClass>>()

        /** Where a constructor is inlined after `operator new`, whose object is no allocated one's. */
        private val inlined = found.inlined.mapTo(mutableSetOf()) { it.at }

        /** Each subobject and what is there, the deepest first, so that a class embeds its members whole. */
        val subobjects: List<Pair<Subobject, ContainingClass>>

        /** The classes with no vtable, each once. */
        val drafts: List<NonPolymorphicClass>

        /** The empty bases of [found]'s polymorphic classes, each class's ([emptyBases]). */
        val emptyBases: Map<ClassDecl, List<NonPolymorphicClass>>

        init {
            // Before anything is decompiled: it gives the empty functions a `this`, which their callers' code shows.
            emptyBases = emptyBases()
            for (m in emptyBases.values.flatten()) m.ctors.forEach { drafted.putIfAbsent(it, m) }
            val heap = if (allocations) allocated else emptyList()
            for (m in heap) m.ctors.forEach { drafted[it] = m }
            // A base's before its deriving classes', so that a class's own fields run follows its bases' grown
            // already. The constructors inlined after `operator new` are their classes' constructors too, with no
            // function.
            val ofFound = found.roles.map { (f, by) ->
                Structor(f, ContainingClass.Existing(by.first), by.second, found.subobjectCalls[f])
            } + found.inlined.flatMap { built ->
                built.parts.map { Structor(null, ContainingClass.Existing(it.cls), CONSTRUCTOR, it.calls) }
            }
            val ofHeap = heap.flatMap { m -> m.ctors.map { Structor(it, m, CONSTRUCTOR) } }
            var structors = ofFound.sortedBy { it.container.decl?.ancestors?.size } + withCalls(ofHeap, monitor)
            while (structors.isNotEmpty() && levels.size < MAX_DEPTH && !monitor.isCancelled) {
                levels += linkedMapOf()
                structors = withCalls(structors.flatMap(::members), monitor)
            }
            subobjects = levels.asReversed().flatMap { it.toList() }
            val merged = drafted.values.map { it.merged }.distinct()
            val reads = dissector.readCalls(merged.flatMap { it.functions }, monitor)
            for (m in merged) {
                m.stores = m.ctors.map { reads.thisStores[it].orEmpty() }.mergedStores()
                for (f in m.functions) m.calls[f] = reads.subobjectCalls[f].orEmpty()
                // A function that both builds one and destroys one is neither's.
                val both = m.ctors intersect m.dtors
                m.ctors -= both
                m.dtors -= both
            }
            drafts = merged + structorBases(merged)
        }

        /**
         * The base this class's structors build at `this` + 0, or null: what its constructors call first there and
         * its destructors last, none of them a known structor, a function [taken] by another class, or one function
         * both call. A destructor takes `this` alone, so one its destructors pass more is a member's method, such as
         * an allocator's `deallocate`, and makes no base. Adds the base's structors to [taken].
         */
        private fun NonPolymorphicClass.baseAtZero(taken: MutableSet<Function>): NonPolymorphicClass? {
            fun Set<Function>.atZero(pick: (Set<Function>) -> Function?) = mapNotNull { f ->
                calls[f].orEmpty()[0L]?.let(pick)?.takeIf {
                    it !in found.roles && it !in taken && it.takesThis()
                }
            }.toSet()
            val base = NonPolymorphicClass()
            base.ctors += ctors.atZero { it.firstOrNull() }.ifEmpty { return null }
            base.dtors += dtors.atZero { it.lastOrNull() }.ifEmpty { return null }
            val passing = dissector.readCalls(dtors, monitor).objectCalls.values.flatten()
                .filter { it.obj == CalledObject.This && it.offset == 0L && it.args > 0 }
                .mapTo(mutableSetOf()) { it.callee }
            if ((base.ctors intersect base.dtors).isNotEmpty() || (base.dtors intersect passing).isNotEmpty()) {
                return null
            }
            taken += base.ctors + base.dtors
            return base
        }

        /**
         * The bases at `this` + 0 of [members] that no other structor builds ([baseAtZero]), and their bases' own,
         * down to [MAX_DEPTH]. One function both structors call there is a method setting up its fields
         * ([helperStores]).
         */
        private fun structorBases(members: List<NonPolymorphicClass>): List<NonPolymorphicClass> = buildList {
            val taken = members.flatMapTo(mutableSetOf()) { it.functions }
            var derived = members
            repeat(MAX_DEPTH) {
                val bases = derived.mapNotNull { it.baseAtZero(taken) }.ifEmpty { return@buildList }
                val uses = dissector.readCalls(bases.flatMap { it.functions }, monitor)
                for (m in bases) {
                    m.stores = m.ctors.map { uses.thisStores[it].orEmpty() }.mergedStores()
                    for (f in m.functions) m.calls[f] = uses.subobjectCalls[f].orEmpty()
                }
                addAll(bases)
                derived = bases
            }
        }

        /**
         * Adds to each of [drafts]' stores what the functions its constructors call on `this` + 0 store, but the
         * structors of a class ([byFunction]): a method setting up its fields, such as one its destructor calls
         * too, or one a compiler folded into its destructor, where its constructor stores nothing itself.
         */
        fun helperStores(byFunction: Map<Function, NonPolymorphicClass>) {
            val helpers = drafts.associateWith { m ->
                m.ctors.flatMap { m.calls[it].orEmpty()[0L].orEmpty() }.distinct().filter { f ->
                    f !in found.roles && byFunction[f].let { it == null || it == m } && f !in m.ctors &&
                        !f.isExternal && f.takesThis()
                }
            }.filterValues { it.isNotEmpty() }.ifEmpty { return }
            val uses = dissector.readCalls(
                helpers.values.flatten().distinct(),
                monitor,
                "Decompiling what member constructors call on this",
            )
            for ((m, fs) in helpers) {
                m.stores = (listOf(m.stores) + fs.map { uses.thisStores[it].orEmpty() }).mergedStores()
            }
        }

        /**
         * Each of [classes]' size: how far its constructors store or its own members, or its base ([bases]), reach,
         * the furthest: the deepest first, so each member's is known by then, but for members of classes merged
         * across levels.
         */
        fun sizes(
            classes: List<NonPolymorphicClass>,
            bases: Map<NonPolymorphicClass, NonPolymorphicClass>,
        ): Map<NonPolymorphicClass, Int> {
            val size = classes.associateWith { m ->
                maxOf(m.stores.maxOfOrNull { (at, dt) -> at + dt.length } ?: 0, m.allocated.toInt())
            }.toMutableMap()
            repeat(MAX_DEPTH) {
                for ((sub, what) in subobjects) {
                    val m = (what as? NonPolymorphicClass)?.merged ?: continue
                    val container = (sub.container as? NonPolymorphicClass)?.merged ?: continue
                    val end = sub.offset.toInt() + (size[m] ?: 0)
                    if (end > (size[container] ?: 0)) size[container] = end
                }
                for ((m, base) in bases) size[m] = maxOf(size[m] ?: 0, size[base] ?: 0)
            }
            return size
        }

        /**
         * The empty bases of the polymorphic classes [found] has constructors of. Such a class keeps its vptr at
         * `this` + 0, so a class with no vtable can only sit there too if it takes no bytes: an empty base. Its
         * constructor does nothing, so its body is a bare return ([hasEmptyBody]), and it is only ever called
         * ([isAddressTaken]). The decompiler then sees no parameter, and so no `this` passed at its calls. Each
         * such function is given one first, and the class's constructors read again: those calling it on
         * `this` + 0 have an empty base it builds, one class for each.
         */
        private fun emptyBases(): Map<ClassDecl, List<NonPolymorphicClass>> {
            val ctors = found.roles.filterValues { (cls, role) -> role == CONSTRUCTOR && cls.vftables.isNotEmpty() }
                .keys
            val empty = ctors.flatMap { it.getCalledFunctions(monitor) }.distinct()
                .filter { it !in found.roles && it !in found.folded && !it.isExternal && it.hasEmptyBody() }
                .filterNot { it.isAddressTaken() }
            if (empty.isEmpty()) return emptyMap()
            for (f in empty.filter { it.parameterCount == 0 }) runCatching { f.giveThis() }
            val callers = ctors.filter { f -> f.getCalledFunctions(monitor).any { it in empty } }
            val uses = dissector.readCalls(callers, monitor, "Decompiling constructors that call empty functions")
            val byFunction = empty.associateWith { f -> NonPolymorphicClass().also { it.ctors += f } }
            return callers.groupBy({ found.roles.getValue(it).first }) { f ->
                uses.subobjectCalls[f].orEmpty()[0L].orEmpty().mapNotNull(byFunction::get)
            }.mapValues { (_, bases) -> bases.flatten().distinct() }.filterValues { it.isNotEmpty() }
        }

        /**
         * The subobjects past `this` + 0 that are bases, not members, each with its class. MSVC builds the virtual
         * bases in the complete object's constructor alone, so the constructor of a class with any takes a flag
         * saying whether to, right after `this`, and stores the vbtables when it does. A class's constructor calls
         * its base's with the flag clear, and stores the vbtables of the base's subobject itself, as the complete
         * object's, where a member's gets the flag set and stores its own: here a constructor of the container
         * calling the subobject's class's constructor at `this` + k with zero, that storing a vbtable at its
         * `this` + j, and the caller one at `this` + k + j.
         */
        fun flaggedBases(): List<Pair<Subobject, ClassDecl>> {
            val candidates = subobjects.filter { (sub, what) ->
                sub.offset > 0 && what.decl != null && sub.container.decl is PlainClass
            }
            fun ctorsOf(c: ContainingClass): Set<Function> = when (c) {
                is ContainingClass.Existing -> found.constructors.filterValues { it == c.cls }.keys
                is NonPolymorphicClass -> c.merged.ctors
            }
            val callers = dissector.readCalls(candidates.flatMap { ctorsOf(it.first.container) }.distinct(), monitor)
            val flagged = callers.objectCalls.mapValues { (_, calls) ->
                calls.filter { it.obj == CalledObject.This && it.offset > 0 && it.flag == 0L && !it.slot }
            }
            val callees = dissector.readCalls(flagged.values.flatten().map { it.callee }.distinct(), monitor)
            return candidates.mapNotNull { (sub, what) ->
                val built = ctorsOf(what)
                val isBase = ctorsOf(sub.container).any { f ->
                    val own = callers.vbtables[f].orEmpty()
                    flagged[f].orEmpty().any { call ->
                        call.offset == sub.offset && call.callee in built &&
                            callees.vbtables[call.callee].orEmpty().keys.any { j -> sub.offset + j in own }
                    }
                }
                what.decl?.takeIf { isBase }?.let { sub to it }
            }
        }

        /** [structors] with what each calls on `this` + k, decompiled. */
        private fun withCalls(structors: List<Structor>, monitor: TaskMonitor): List<Structor> {
            val uses = dissector.readCalls(structors.mapNotNull { it.function }, monitor)
            return structors.map { it.copy(calls = uses.subobjectCalls[it.function]) }
        }

        /**
         * The member objects [s] builds or destroys, put in the deepest level, and the structors of theirs it is
         * the first to call: to read next.
         */
        private fun members(s: Structor): List<Structor> = s.calls.orEmpty().mapNotNull { (offset, called) ->
            val sub = Subobject(s.container, offset)
            val structor = memberStructor(s.function, sub, s.role, called) ?: return@mapNotNull null
            val there = levels.firstNotNullOfOrNull { it[sub] }
            if (there is ContainingClass.Existing) return@mapNotNull null
            val member = (there as? NonPolymorphicClass)?.merged
            val before = drafted[structor]?.merged
            val into = member ?: before ?: NonPolymorphicClass()
            if (member != null && before != null) member.absorb(before)
            if (there == null) levels.last()[sub] = into
            drafted.putIfAbsent(structor, into)
            val role = if (s.role == CONSTRUCTOR) into.ctors else into.dtors
            Structor(structor, into, s.role).takeIf { role.add(structor) }
        }

        /**
         * The structor of the member at [sub] that [f], a [role] of its container, [called] there: the first it calls
         * if it builds, the last if it destroys. Null where that's a structor [found] already, whose class is then
         * at [sub].
         */
        private fun memberStructor(f: Function?, sub: Subobject, role: StructorRole, called: Set<Function>): Function? {
            val structor = when (role) {
                CONSTRUCTOR -> called.first()
                DESTRUCTOR -> called.last()
                else -> return null
            }
            if (sub.offset <= 0L || structor == f || !structor.takesThis()) return null
            val (cls, builtRole) = found.roles[structor] ?: return structor
            if (role == CONSTRUCTOR && builtRole == CONSTRUCTOR && sub.container != ContainingClass.Existing(cls)) {
                if (levels.none { sub in it }) levels.last()[sub] = ContainingClass.Existing(cls)
            }
            return null
        }

        /**
         * The classes of the objects `operator new` allocates with a constant size whose constructor, the first
         * function called on what it returns ([ThisFunctionDissector.allocations]), [found] doesn't know: one class
         * for each, which merges with any member's it builds too, at least as large as allocated. Not where that
         * function is no method, has a name of its own outside a class, as a library function has, takes it as the
         * object it returns ([returnsInSlot]), or is the first called after allocations of different sizes, which no
         * one class's constructor is.
         */
        private val allocated: List<NonPolymorphicClass> get() = dissector.allocations(monitor)
            .filter { it.at !in inlined }
            .groupBy { it.firstCalled }
            .mapNotNull { (ctor, allocs) ->
                val sizes = allocs.mapTo(sortedSetOf()) { it.size }
                when {
                    ctor in found.roles || ctor.isExternal -> null

                    // What it allocates is the object a function returning one by value fills, not its `this`.
                    ctor.returnsInSlot() -> null.also {
                        debug("member-allocated-return-slot", "${ctor.name} returns into what operator new allocates")
                    }

                    !ctor.takesThis() -> null

                    ctor.symbol.source != SourceType.DEFAULT && ctor.parentNamespace !is GhidraClass -> null

                    sizes.size > 1 -> null.also {
                        debug("member-allocated-sizes", "${ctor.name} first called after allocations of sizes $sizes")
                    }

                    else -> NonPolymorphicClass().apply {
                        ctors += ctor
                        allocated = sizes.single()
                        debug("member-allocated", "${ctor.name} builds what operator new(${sizes.single()}) allocates")
                    }
                }
            }
    }

    /**
     * Whether code or data takes [this]'s address rather than calling it: a vtable slot, as a compiler shares one
     * empty function among the no-op virtuals of many classes. A constructor is only ever called.
     */
    private fun Function.isAddressTaken() = program.addressTakers(entryPoint).any()

    /**
     * Gives each of [members] the base its structors build at `this` + 0, the class of another of [members]
     * ([byFunction]): the one its constructor calls first there, or its destructor last. Where its constructor
     * calls a polymorphic class's first there, that class goes [atZero]. Returns each class given a base, and
     * that base.
     */
    private fun addNonPolymorphicBases(
        members: List<NonPolymorphicClass>,
        byFunction: Map<Function, NonPolymorphicClass>,
        found: FoundStructors,
        atZero: MutableList<Pair<Subobject, ContainingClass>>,
    ): Map<NonPolymorphicClass, NonPolymorphicClass> = buildMap {
        for (m in members) {
            val cls = m.cls ?: continue
            val first = m.ctors.mapNotNull { m.calls[it].orEmpty()[0L]?.firstOrNull() }
            val last = m.dtors.mapNotNull { m.calls[it].orEmpty()[0L]?.lastOrNull() }
            first.firstNotNullOfOrNull { f -> found.roles[f]?.takeIf { it.second == CONSTRUCTOR }?.first }
                ?.let { atZero += Subobject(m, 0L) to ContainingClass.Existing(it) }
            val structors = first.filter { f -> byFunction[f]?.ctors?.contains(f) == true } +
                last.filter { f -> byFunction[f]?.dtors?.contains(f) == true }
            val base = structors.map(byFunction::getValue)
                .firstOrNull { it != m && it.cls?.derivesFrom(cls) == false } ?: continue
            cls.bases += ClassBase(base.cls!!, isVirtual = false, access = null, 0L)
            debug("base-inferred-structor", "${cls.name} : ${base.cls!!.name}, off the structor it calls on `this`")
            put(m, base)
        }
    }

    /** Adds each of [flagged] as a base of its container at its offset, and returns the classes given one. */
    private fun addFlaggedBases(flagged: List<Pair<Subobject, ClassDecl>>): List<ClassDecl> = flagged.mapNotNull {
        val (sub, base) = it
        val cls = sub.container.decl as? PlainClass ?: return@mapNotNull null
        if (base == cls || base.derivesFrom(cls) || cls.bases.any { b -> b.cls == base }) return@mapNotNull null
        cls.bases += ClassBase(base, isVirtual = false, access = null, sub.offset)
        debug("base-inferred-flag", "${cls.name} : ${base.name} at +${sub.offset}, built with no virtual bases")
        cls
    }.distinct()

    /** Adds each of [empty]'s classes as a base at offset 0 of its class, and returns the classes given one. */
    private fun addEmptyBases(empty: Map<ClassDecl, List<NonPolymorphicClass>>): List<ClassDecl> =
        empty.mapNotNull { (cls, bases) ->
            val own = (cls as? PlainClass)?.bases ?: return@mapNotNull null
            val added = bases.mapNotNull { it.cls }.distinct()
                .filter { b -> b != cls && own.none { it.cls == b } }
                .onEach { b ->
                    own += ClassBase(b, isVirtual = false, access = null, 0L)
                    debug("base-inferred-empty", "${cls.name} : ${b.name}, off the constructor it calls on `this`")
                }
            cls.takeIf { added.isNotEmpty() }
        }

    /** The class structs the class passes made: each named as its class's category is, under the classes' root. */
    private fun classStructs() = dtm.allStructures.asSequence().filter {
        it.categoryPath.isAncestorOrSelf(ClassNaming.classDataTypesRoot) && it.name == it.categoryPath.name
    }.toList()

    /**
     * The class [this] builds: the one a structor of it is named in already, by a user or an analysis, else
     * `NPKlass_<address>` after its first constructor, or destructor: that function's address, as it has no vtable.
     */
    private fun NonPolymorphicClass.buildClass() {
        val first = ctors.minByOrNull { it.entryPoint } ?: dtors.minByOrNull { it.entryPoint } ?: return
        if (namedClass == null) namedAfter = first to if (first in ctors) CONSTRUCTOR else DESTRUCTOR
        val ns = namedClass ?: program.symbolTable.buildClassNamespaces(
            listOf("$NON_POLYMORPHIC_PREFIX${first.entryPoint}"),
            GenericVftableFinder.SEEDED,
        )
        cls = PlainClass(ns, emptyList())
    }

    /**
     * Says in the description of [ns]'s struct, where it has none, that its name is [structor]'s address, not a
     * vtable's.
     */
    private fun describe(ns: GhidraClass, structor: Function, role: StructorRole) {
        val struct = program.classStruct(ns)?.takeIf { it.description.isNullOrEmpty() } ?: return
        val what = if (role == CONSTRUCTOR) "constructor" else "destructor"
        struct.description = "No vtable: named after its first $what, at ${structor.entryPoint}"
    }

    /**
     * Names [this] [ns]'s constructor or destructor and moves it there, where nothing named it, its convention
     * then a method's ([fixMethodConvention]: the `__fastcall` Ghidra takes a function reading only ECX for
     * becomes a `__thiscall`).
     */
    private fun Function.name(ns: GhidraClass, role: StructorRole) {
        if (symbol.source != SourceType.DEFAULT) return
        runCatching {
            parentNamespace = ns
            setName(if (role == CONSTRUCTOR) ns.name else "~${ns.name}", SourceType.ANALYSIS)
            program.recordPlaced(this, role, virtual = false)
            fixMethodConvention(takesThis = true)
        }.onFailure { warn("member-structor-unnamed", "$name -> ${ns.qualifiedName}: $it", entryPoint) }
    }

    /**
     * Whether [this] takes `this` where a method does ([takesThisAt]), so a pointer into an object passed first is
     * its object. Unknown, so taken, where it has no parameters yet.
     */
    private fun Function.takesThis() = takesThisAt(thisStorage) || (!isExternal && parameterCount == 0)

    private fun structOf(cls: ClassDecl): Structure? = cls.ns?.toClass()?.let(program::classStruct)

    private fun writeRecords(classes: Collection<ClassDecl>) {
        val entries = classes.mapNotNull { cls ->
            ClassHierarchyRecords.entryOf(cls, structOf(cls)?.let(dtm::getID)?.takeIf { it >= 0 })
        }
        program.writeClassRecord(program.readClassRecord().orEmpty() + entries)
    }

    companion object {
        /** How deep members of members go. */
        private const val MAX_DEPTH = 4

        /** The prefix of a non-polymorphic class this pass names after its first constructor's address. */
        const val NON_POLYMORPHIC_PREFIX = "NPKlass_"
    }
}
