package ghicpp.recover

import ghicpp.*
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghicpp.MemberAttrs.Companion.recordPlaced
import ghicpp.abi.PlainVtables
import ghicpp.abi.StructorRole
import ghicpp.abi.StructorRole.CONSTRUCTOR
import ghicpp.abi.StructorRole.DESTRUCTOR
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.buildClassNamespaces
import ghistabs.componentsOverlapping
import ghistabs.diagnose.DiagnosticSink
import ghistabs.includes
import ghistabs.lay
import ghistabs.range
import ghistabs.stretch
import ghistabs.toClass
import ghistabs.withLength

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
 * A call at `this` + 0 builds a base, which the class pass reads. An ordinary method a constructor calls first
 * on a member with no constructor of its own looks the same as one, so this is a guess, as the pass's are.
 */
class MemberObjectPass(
    private val program: Program,
    sink: DiagnosticSink,
    /** Whether a field a constructor fills in a counted loop or with `memset` is an array ([StructorInspector]). */
    private val fillArrays: Boolean = true,
) : DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val thisStorage = program.thisStorage()

    /**
     * The members, or bases, whose class the pass found already, a class with a vtable whose constructor
     * another's calls on `this` + k: laid there whole too.
     */
    private val known = linkedMapOf<Subobject, ClassDecl>()

    /** The class a subobject is in: one the class pass found, or a [NonPolymorphicClass] this pass drafts. */
    private sealed interface ContainingClass {
        /** A class the class pass found. */
        data class Existing(val cls: ClassDecl) : ContainingClass
    }

    /**
     * A class with no vtable, known only from its structors: those a found class's structors call on `this` + k,
     * what its constructors store, and the class it's given.
     */
    private class NonPolymorphicClass : ContainingClass {
        val ctors = mutableSetOf<Function>()
        val dtors = mutableSetOf<Function>()
        var stores: Map<Int, DataType> = emptyMap()
        var cls: PlainClass? = null

        /** The structor this pass named [cls] after, and its role, where nothing named it already. */
        var namedAfter: Pair<Function, StructorRole>? = null
        val functions get() = ctors + dtors
    }

    /** The subobject at [offset] in [container]. */
    private data class Subobject(val container: ContainingClass, val offset: Long)

    /** Recovers the classes of the member objects of [found]'s classes, and returns how many it made or found again. */
    fun run(found: FoundStructors, monitor: TaskMonitor = TaskMonitor.DUMMY): Int {
        val held = collect(found, monitor)
        val root = merge(held.values.distinct())
        val members = held.values.map(root::getValue).distinct()
        for (m in members) m.cls = classFor(m)
        val classes = members.filter { it.cls != null }
        val sizes = sizes(classes, held.mapValues { (_, m) -> root.getValue(m) }, root)
        monitor.initialize(classes.size.toLong(), "Naming member object classes' constructors and destructors")
        for (m in classes) {
            monitor.increment()
            val ns = m.cls?.ns?.toClass() ?: continue
            m.ctors.forEach { name(it, ns, CONSTRUCTOR) }
            m.dtors.forEach { name(it, ns, DESTRUCTOR) }
            val size = sizes[m] ?: 0
            runCatching { program.sizeClassStruct(ns, size) }
                .onFailure { warn("member-struct-unsized", "${ns.getName(true)} -> $size: $it") }
            m.namedAfter?.let { (f, role) -> describe(ns, f, role) }
        }
        monitor.message = "Filling member object class structs"
        ClassStructFiller(program, PlainVtables, this)
            .fillAll(classes.mapNotNull { it.cls }, classes.associate { it.cls!! to it.stores })
        // The deepest members first, so a class embeds its members whole.
        val order = held.keys.sortedByDescending { sub ->
            (sub.container as? NonPolymorphicClass)?.let { held.values.indexOf(it) } ?: -1
        }
        fun containerOf(sub: Subobject) = when (val h = sub.container) {
            is NonPolymorphicClass -> root[h]?.cls
            is ContainingClass.Existing -> h.cls
        }?.let(::structOf)
        monitor.initialize((order.size + known.size).toLong(), "Laying member objects in their classes")
        for (sub in order) {
            monitor.increment()
            val member = root.getValue(held.getValue(sub)).cls?.let(::structOf)?.takeUnless { it.isZeroLength }
            if (member != null) containerOf(sub)?.placeMember(sub.offset.toInt(), member)
        }
        for ((sub, cls) in known) {
            monitor.increment()
            val member = structOf(cls)?.takeUnless { it.isZeroLength } ?: continue
            containerOf(sub)?.placeMember(sub.offset.toInt(), member)
        }
        writeRecords(classes.mapNotNull { it.cls })
        return classes.size
    }

    /**
     * The members [found]'s structors build and destroy, by where they are, then those members' own, decompiled,
     * down to [MAX_DEPTH].
     */
    private fun collect(found: FoundStructors, monitor: TaskMonitor): Map<Subobject, NonPolymorphicClass> {
        val inspector = StructorInspector(program, emptyList(), this, fillArrays)
        val held = linkedMapOf<Subobject, NonPolymorphicClass>()
        known.clear()
        var structors: Map<Function, Pair<ContainingClass, StructorRole>> =
            found.roles.mapValues { (_, by) -> ContainingClass.Existing(by.first) to by.second }
        var calls = found.subobjectCalls
        for (depth in 1..MAX_DEPTH) {
            if (monitor.isCancelled) break
            val fresh = linkedSetOf<NonPolymorphicClass>()
            for ((f, by) in structors) {
                for ((offset, called) in calls[f].orEmpty()) {
                    val sub = Subobject(by.first, offset)
                    val structor = memberStructor(f, sub, by.second, called, found) ?: continue
                    val member = held.getOrPut(sub) { NonPolymorphicClass().also(fresh::add) }
                    (if (by.second == CONSTRUCTOR) member.ctors else member.dtors) += structor
                }
            }
            if (fresh.isEmpty()) break
            val uses = inspector.readCalls(fresh.flatMap { it.functions }, monitor)
            for (m in fresh) m.stores = mergedStores(m.ctors.map { uses.thisStores[it].orEmpty() })
            structors = fresh.flatMap { m ->
                m.ctors.map { it to (m to CONSTRUCTOR) } + m.dtors.map { it to (m to DESTRUCTOR) }
            }.toMap()
            calls = uses.subobjectCalls
        }
        return held
    }

    /**
     * The structor of the member at [sub] that [f], a [role] of its container, [called] there: the first it calls
     * if it builds, the last if it destroys. Null where that's a structor [found] already, whose class is
     * [known] at [sub] then.
     */
    private fun memberStructor(
        f: Function,
        sub: Subobject,
        role: StructorRole,
        called: Set<Function>,
        found: FoundStructors,
    ): Function? {
        val structor = when (role) {
            CONSTRUCTOR -> called.first()
            DESTRUCTOR -> called.last()
            else -> return null
        }
        if (sub.offset <= 0L || structor == f || !structor.takesThis()) return null
        val built = found.roles[structor] ?: return structor
        if (role == CONSTRUCTOR && built.second == CONSTRUCTOR &&
            ContainingClass.Existing(built.first) != sub.container
        ) {
            known.putIfAbsent(sub, built.first)
        }
        return null
    }

    /**
     * Each of [members] mapped to the one it's merged into with those it shares a structor with. A function that
     * both builds one and destroys one is neither's.
     */
    private fun merge(members: List<NonPolymorphicClass>): Map<NonPolymorphicClass, NonPolymorphicClass> {
        val into = members.associateWith { it }.toMutableMap()
        fun find(m: NonPolymorphicClass): NonPolymorphicClass {
            var r = m
            while (into.getValue(r) != r) r = into.getValue(r)
            into[m] = r
            return r
        }
        val byFunction = mutableMapOf<Function, NonPolymorphicClass>()
        for (m in members) {
            for (f in m.functions) {
                val (a, b) = find(byFunction.getOrPut(f) { m }) to find(m)
                if (a == b) continue
                a.ctors += b.ctors
                a.dtors += b.dtors
                a.stores = mergedStores(listOf(a.stores, b.stores))
                into[b] = a
            }
        }
        for (m in members.map(::find).distinct()) {
            val both = m.ctors intersect m.dtors
            m.ctors -= both
            m.dtors -= both
        }
        return members.associateWith(::find)
    }

    /**
     * The class [m] builds: the one a structor of it is named in already, by a user or an analysis, else
     * `NPKlass_<address>` after its first constructor, or destructor: that function's address, as it has no vtable.
     */
    private fun classFor(m: NonPolymorphicClass): PlainClass? {
        val named = m.functions.firstNotNullOfOrNull { f ->
            (f.parentNamespace as? GhidraClass)?.takeIf { f.symbol.source != SourceType.DEFAULT }
        }
        val first = m.ctors.minByOrNull { it.entryPoint } ?: m.dtors.minByOrNull { it.entryPoint } ?: return null
        if (named == null) m.namedAfter = first to if (first in m.ctors) CONSTRUCTOR else DESTRUCTOR
        val ns = named ?: program.symbolTable.buildClassNamespaces(
            listOf("$NON_POLYMORPHIC_PREFIX${first.entryPoint}"),
            GenericVftableFinder.SEEDED,
        )
        return PlainClass(ns, emptyList())
    }

    /** Each member object class's size: how far its constructors store or its own members reach, the further. */
    private fun sizes(
        classes: List<NonPolymorphicClass>,
        held: Map<Subobject, NonPolymorphicClass>,
        root: Map<NonPolymorphicClass, NonPolymorphicClass>,
    ): Map<NonPolymorphicClass, Int> {
        val size = classes.associateWith { m -> m.stores.maxOfOrNull { (at, dt) -> at + dt.length } ?: 0 }
            .toMutableMap()
        repeat(MAX_DEPTH) {
            for ((sub, m) in held) {
                val container = (sub.container as? NonPolymorphicClass)?.let(root::getValue) ?: continue
                val end = sub.offset.toInt() + (size[m] ?: 0)
                if (end > (size[container] ?: 0)) size[container] = end
            }
        }
        return size
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

    /** Names [func] [ns]'s constructor or destructor and moves it there, where nothing named it. */
    private fun name(func: Function, ns: GhidraClass, role: StructorRole) {
        if (func.symbol.source != SourceType.DEFAULT) return
        runCatching {
            func.parentNamespace = ns
            func.setName(if (role == CONSTRUCTOR) ns.name else "~${ns.name}", SourceType.ANALYSIS)
            program.recordPlaced(func, role, virtual = false)
        }.onFailure { warn("member-structor-unnamed", "${func.name} -> ${ns.getName(true)}: $it", func.entryPoint) }
    }

    /**
     * Whether [this] takes `this` where a method does ([takesThisAt]), so a pointer into an object passed first is
     * its object. Unknown, so taken, where it has no parameters yet.
     */
    private fun Function.takesThis() = takesThisAt(thisStorage) || (!isExternal && parameterCount == 0)

    private fun structOf(cls: ClassDecl): Structure? = cls.ns?.toClass()?.let(program::classStruct)

    /**
     * Lays [member] at [at] in this. Where it overlaps this class's own `<Class>_data` struct, it goes in there
     * over the plain fields there, and that struct [stretch]es to hold it where the member starts before or ends
     * past it. In a base's struct holding all of it, it goes only over undefined bytes. Anything else in the way,
     * a vptr, a base, another member, leaves it unplaced, with a warning.
     */
    private fun Structure.placeMember(at: Int, member: Structure) {
        if (member == this) return
        val range = at.withLength(member.length)
        val field = "field_0x${at.toString(16)}"
        val inWay = componentsOverlapping(range).filterNot { it.isAt(at, member) }
        val (own, others) = inWay.partition { isOwnData(it) }
        val base = others.singleOrNull()?.takeIf { it.dataType is Structure && it.range.includes(range) }
        val (into, offset) = when {
            base != null -> (base.dataType as Structure).let { inner ->
                val within = at - base.offset
                if (inner.getComponentAt(within)?.isAt(within, member) == true) return
                inner.layoutProblem(within, member)?.let { return unplaced(field, member, it) }
                inner to within
            }

            others.isNotEmpty() || own.size > 1 ->
                return unplaced(field, member, "overlaps ${(others + own.drop(1)).joinToString { it.describe() }}")

            own.isEmpty() -> this to at

            else -> {
                val data = own.single()
                val start = minOf(data.offset, at)
                stretch(data, range) to at - start
            }
        }
        val clash = into.componentsOverlapping(offset, member.length)
            .filter { it.dataType is Structure && !it.isAt(offset, member) }
        if (clash.isNotEmpty()) {
            return unplaced(field, member, "overlaps ${clash.joinToString { it.describe() }} in ${into.name}")
        }
        runCatching { into.lay(offset, member, field, "member or base") }
            .onSuccess { debug("member-placed", "${member.name} at +$at in $name") }
            .onFailure { degradation("member-unplaced", "$name::$field", it.message) }
    }

    private fun Structure.unplaced(field: String, member: Structure, why: String) =
        degradation("member-unplaced", "$name::$field", "${member.name} $why")

    /** Whether this is [member] laid at [at] already. */
    private fun DataTypeComponent.isAt(at: Int, member: Structure) = dataType == member && offset == at

    private fun DataTypeComponent.describe() = "${fieldName ?: dataType.name} at +0x${offset.toString(16)}"

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
