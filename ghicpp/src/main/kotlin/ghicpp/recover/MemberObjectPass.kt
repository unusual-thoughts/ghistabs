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
 * A call at `this` + 0 builds a base, which the class pass reads. An ordinary method a constructor calls first
 * on a member with no constructor of its own looks the same as one, so this is a guess, as the pass's are.
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
        val classes = objects.drafts.filter { it.cls != null }
        val sizes = objects.sizes(classes)
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
        monitor.initialize(objects.subobjects.size.toLong(), "Laying member objects in their classes")
        for ((sub, what) in objects.subobjects) {
            monitor.increment()
            val member = what.decl?.let(::structOf)?.takeUnless { it.isZeroLength } ?: continue
            sub.container.decl?.let(::structOf)?.let { placeMember(it, sub.offset.toInt(), member) }
        }
        // The members grew the classes they went past the end of, and with them those deriving from them.
        dtm.growToHoldBases(classStructs())
        writeRecords(plainClasses)
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

        init {
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
            drafts = drafted.values.map { it.merged }.distinct()
            val reads = dissector.readCalls(drafts.flatMap { it.ctors }, monitor)
            for (m in drafts) {
                m.stores = m.ctors.map { reads.thisStores[it].orEmpty() }.mergedStores()
                // A function that both builds one and destroys one is neither's.
                val both = m.ctors intersect m.dtors
                m.ctors -= both
                m.dtors -= both
            }
        }

        /**
         * Each of [classes]' size: how far its constructors store or its own members reach, the further: the
         * deepest first, so each member's is known by then, but for members of classes merged across levels.
         */
        fun sizes(classes: List<NonPolymorphicClass>): Map<NonPolymorphicClass, Int> {
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
            }
            return size
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
