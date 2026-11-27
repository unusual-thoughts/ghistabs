package ghicpp.score

import ghicpp.ClassNaming
import ghicpp.VirtKind
import ghicpp.abi.itanium.ItaniumStructor
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.*
import ghicpp.nameSegments
import ghidra.program.model.address.Address

/** True positives, false positives and false negatives of one thing a recovery claims. */
data class Tally(val tp: Int = 0, val fp: Int = 0, val fn: Int = 0) {
    operator fun plus(o: Tally) = Tally(tp + o.tp, fp + o.fp, fn + o.fn)

    val precision: Double? get() = (tp + fp).takeIf { it > 0 }?.let { tp.toDouble() / it }
    val recall: Double? get() = (tp + fn).takeIf { it > 0 }?.let { tp.toDouble() / it }

    companion object {
        /** [claimed] against [actual]: what both hold, what only the claim does, what only the truth does. */
        fun <T> of(claimed: Collection<T>, actual: Collection<T>): Tally {
            val c = claimed.toSet()
            val a = actual.toSet()
            return Tally((c intersect a).size, (c - a).size, (a - c).size)
        }
    }
}

/**
 * The ground truth a recovery is scored against. [hierarchy] is the class view of a binary whose classes
 * are known (a stabs import, its symbols); [scope] the classes in it a recovery from the bare binary is
 * asked to find. [sameBinary] when the truth's addresses are the subject's own (a twin the subject was
 * stripped from), so vtables and methods compare by address; [sameLayout] when its sizes and offsets are
 * the subject's ABI's and pointer size's. [membersKnown] when the truth's class members are known rather than
 * recovered themselves, so methods are scored.
 */
data class Truth(
    val snapshot: Snapshot,
    val scope: Set<Long>,
    val sameBinary: Boolean,
    val sameLayout: Boolean,
    val membersKnown: Boolean = sameBinary,
) {
    val hierarchy: ClassHierarchy get() = snapshot.hierarchy

    companion object {
        /**
         * The classes a stabs import described that a recovery could find: those with a vtable or a function
         * of their own. A plain C struct, or a class whose members were all inlined, leaves nothing to find.
         */
        fun describedScope(h: ClassHierarchy): Set<Long> = h.classes
            .filter { it.origin == Origin.STABS && (it.vftable != null || it.functions().isNotEmpty()) }
            .mapTo(HashSet()) { it.id }

        /** [snapshot]'s own classes, the ones in [scope] described with [source]'s bases, by qualified name. */
        fun Snapshot.withBasesOf(source: ClassHierarchy, scope: Set<Long>): Snapshot {
            val byName = hierarchy.classes.associateBy { it.qualifiedName }
            val sourceNames = source.classes.associate { it.id to it.qualifiedName }
            val classes = hierarchy.classes.map { cls ->
                val described = source.classes.firstOrNull { it.qualifiedName == cls.qualifiedName && it.id in scope }
                    ?: return@map cls
                cls.copy(
                    bases = described.bases.map { b ->
                        val name = b.targetId?.let(sourceNames::get) ?: b.name
                        b.copy(name = name, targetId = byName[name]?.id, offset = null)
                    },
                )
            }
            return copy(hierarchy = ClassHierarchy(classes))
        }
    }
}

/**
 * One recovery scored against its [Truth]. [tallies] holds a [Tally] per attribute, [instances] lists each false
 * positive and false negative under its counter (`<attribute>-fp` or `-fn`), and [notes] says what was left
 * unscored.
 */
data class Scorecard(
    val tallies: Map<String, Tally>,
    val instances: Map<String, List<String>> = emptyMap(),
    val notes: List<String> = emptyList(),
) {
    /** The tallies as baseline counters: `<attribute>-tp`, `-fp`, `-fn`. */
    fun counters(): Map<String, Long> = tallies.flatMap { (name, t) ->
        listOf("$name-tp" to t.tp.toLong(), "$name-fp" to t.fp.toLong(), "$name-fn" to t.fn.toLong())
    }.toMap()

    /**
     * Every instance as one line, `<counter> <instance>`, sorted: the committed baseline of what each counter
     * counts, which diffs a line per instance that came or went.
     */
    fun instanceLines(): List<String> = instances.flatMap { (counter, list) -> list.map { "$counter $it" } }.sorted()

    fun markdown(title: String): String = buildString {
        appendLine("# $title")
        appendLine()
        appendLine("| attribute | TP | FP | FN | precision | recall |")
        appendLine("| --- | ---: | ---: | ---: | ---: | ---: |")
        for ((name, t) in tallies) {
            appendLine("| $name | ${t.tp} | ${t.fp} | ${t.fn} | ${t.precision.pct()} | ${t.recall.pct()} |")
        }
        for (name in tallies.keys) {
            val fp = instances["$name-fp"].orEmpty()
            val fn = instances["$name-fn"].orEmpty()
            if (fp.isEmpty() && fn.isEmpty()) continue
            appendLine()
            appendLine("## $name")
            for ((label, list) in listOf("False positives" to fp, "False negatives" to fn)) {
                if (list.isEmpty()) continue
                appendLine()
                appendLine("$label (${list.size}):")
                appendLine()
                list.sorted().forEach { appendLine("- $it") }
            }
        }
        if (notes.isNotEmpty()) {
            appendLine()
            appendLine("## Not scored")
            appendLine()
            notes.sorted().forEach { appendLine("- $it") }
        }
    }

    private fun Double?.pct() = this?.let { "%.1f%%".format(it * 100) } ?: "–"

    companion object {
        /** The order attributes are reported in, and the ones a truth may not be able to score. */
        val ATTRIBUTES = listOf(
            "classes", "polymorphic-classes", "class-splits", "bases", "base-access", "base-offsets", "vftables",
            "abstract",
            "methods", "virtual-methods", "structors", "sizes", "fields", "field-sizes",
        )
    }
}

/** A class's own functions: not a thunk nor an import. */
private fun ClassView.functions() = members.filter { it.kind == MemberKind.FUNCTION && it.library == null }

/**
 * Where [this] member is, as an offset. Truth and subject are different programs, or no program at all (a
 * committed truth file, OOAnalyzer's results), and an [Address] equals only one in a like address space; the
 * offset is what they share, so the scorer compares by it.
 */
private val Member.at: Long get() = address.offset

private fun ghicpp.Access.publicness() = if (this == ghicpp.Access.PUBLIC) "public" else "non-public"

/** Where a class's name comes from the binary: its RTTI or a symbol's namespace. */
private val NAMED = setOf(Origin.MSVC_RTTI, Origin.ITANIUM_RTTI, Origin.SWEPT_RTTI, Origin.NAMESPACE)

/**
 * Scores [subject], what a recovery from a bare binary made of its classes, against [truth].
 *
 * Each subject class is matched to a truth class by its qualified name, else by the vtable it labels, else by
 * the truth class that most of its functions belong to. When two truth classes tie on functions, the subject
 * class's own structors decide.
 *
 * A subject class with no match is a false class. When a truth class already has a better match, another
 * subject class matched to it is a split: a piece of that class that the recovery set apart. Splits count under
 * `class-splits` instead of `classes`, and their functions count for the class they were split from. A subject
 * class matched to a truth class outside [Truth.scope] (a library class whose vtable is known but not
 * described) is not scored.
 *
 * Every other attribute is scored over the matched pairs in scope, comparing the truth class's bases, vtable,
 * members and layout with the subject's. They are compared by address where [Truth.sameBinary], by offset where
 * [Truth.sameLayout], and not at all where the truth can't tell.
 */
class Scorer(
    private val truth: Truth,
    private val subject: Snapshot,
    /** The addresses that the truth's vtable words hold, read from the binary. Null when the binary isn't at hand. */
    private val vtableSlots: Set<Long>? = null,
) {
    private val t = truth.hierarchy
    private val s = subject.hierarchy
    private val instances = linkedMapOf<String, MutableList<String>>()
    private val notes = mutableListOf<String>()

    /** Records [what] as a false positive of [attribute]. */
    private fun fp(attribute: String, what: String) {
        instances.getOrPut("$attribute-fp") { mutableListOf() } += what
    }

    /** Records [what] as a false negative of [attribute]. */
    private fun fn(attribute: String, what: String) {
        instances.getOrPut("$attribute-fn") { mutableListOf() } += what
    }

    private val truthByName = t.classes.groupBy { it.qualifiedName }
    private val truthFunctionOwner: Map<Long, Long> = t.classes
        .flatMap { c -> c.functions().map { it.at to c.id } }.toMap()
    private val truthVtables = truth.snapshot.vtables.sortedBy { it.start }
    private val truthVtableClasses = truthVtables.mapTo(HashSet()) { it.classId }

    /** This-adjusting thunks: what the truth lists apart from its functions, and a recovery may well call one. */
    private val truthThunks: Set<Long> = t.classes
        .flatMap { c -> c.members.filter { it.kind == MemberKind.THUNK }.map { it.at } }.toSet()

    /**
     * The truth class whose vtable label's extent holds [at], an address point. Where an Itanium group's header
     * opens right at it, the table there is one with no slots before it, as a construction vtable for a base whose
     * only virtual thing is a virtual base can be, not the group's.
     */
    private fun vtableOwner(at: Long): Long? =
        truthVtables.lastOrNull { it.start <= at && !(it.start == at && at in truthGroupHeaders) }
            ?.takeIf { at < it.end }?.classId

    /** Where the truth's Itanium vtable groups begin: their `vtable` labels, in front of their headers. */
    private val truthGroupHeaders: Set<Long> = t.classes.flatMap { c -> c.members }
        .filter { it.kind == MemberKind.VTABLE && it.name == ClassNaming.VTABLE }.mapTo(HashSet()) { it.at }

    /**
     * The truth class that [cls] stands for, and how strong the match is: 3 by name, 2 by vtable, 1 by most of its
     * functions, and 0 by name alone for a class with neither a vtable nor any functions. A name alone is the
     * weakest match because exception records (MSVC's `catch` type descriptors) name classes even without RTTI,
     * so another subject class may be a better match for the same truth class.
     */
    private fun matchOf(cls: ClassView): Pair<Long, Int>? {
        truthByName[cls.qualifiedName]?.let { named ->
            val strength = if (cls.vftable == null && cls.functions().isEmpty()) 0 else 3
            return (named.firstOrNull { it.id in truth.scope } ?: named.first()).id to strength
        }
        if (!truth.sameBinary) return null
        cls.vftable?.let { vtableOwner(it.offset) }?.let { return it to 2 }
        val functions = cls.functions()
        val votes = functions.mapNotNull { truthFunctionOwner[it.at] }.groupingBy { it }.eachCount()
        val most = votes.values.maxOrNull() ?: return null
        val leaders = votes.filterValues { it == most }.keys
        // A class that holds a stray function of another class, such as its base, is still the class its structors
        // belong to.
        val owner = leaders.singleOrNull()
            ?: functions.filter { cls.isStructorName(it.name) }.mapNotNull { truthFunctionOwner[it.at] }
                .distinct().filter { it in leaders }.singleOrNull()
        return owner?.let { it to 1 }
    }

    /** The subject's classes worth scoring: anything the recovery found or named, not an import's namespace. */
    private val candidates = s.classes.filter { it.origin != Origin.LIBRARY && !s.isEmpty(it) }

    private val matches: Map<Long, Pair<Long, Int>> =
        candidates.mapNotNull { c -> matchOf(c)?.let { c.id to it } }.toMap()

    /** Truth id to the subject class standing for it: the strongest match, then the one with most functions. */
    private val pairs: Map<Long, ClassView> = candidates.filter { it.id in matches }
        .groupBy { matches.getValue(it.id).first }
        .mapValues { (_, list) ->
            list.maxWith(compareBy({ matches.getValue(it.id).second }, { it.functions().size }, { -it.id }))
        }

    /** The truth class a subject class (by id) stands for, when it is the one that does. */
    private val truthOf: Map<Long, Long> = pairs.entries.associate { (tid, sc) -> sc.id to tid }

    private val scoredPairs = pairs.filterKeys { it in truth.scope }.map { (tid, sc) -> t[tid]!! to sc }

    /** The splits of each truth class (by id): the other subject classes matched to it. */
    private val splits: Map<Long, List<ClassView>> = candidates
        .filter { it.id in matches && it.id !in truthOf }
        .groupBy { matches.getValue(it.id).first }

    private fun ClassView.describe() = "`$qualifiedName` (${origin.name.lowercase()}${vftable?.let {
        ", vftable $it"
    }.orEmpty()})"

    fun score(): Scorecard {
        val tallies = linkedMapOf<String, Tally>()
        tallies["classes"] = classes(polymorphic = false)
        tallies["polymorphic-classes"] = classes(polymorphic = true)
        tallies["class-splits"] = classSplits()
        bases(tallies)
        // Across ABIs a class's vftables differ (MSVC gives a class whose only virtuals are its virtual base's none).
        if (truth.sameBinary) tallies["vftables"] = vftables()
        tallies["abstract"] = abstract()
        if (truth.membersKnown) {
            tallies["methods"] = methods("methods", { _, _ -> true }) { true }
            tallies["virtual-methods"] =
                methods("virtual-methods", ::isTrulyVirtual) { it.attrs?.virt == VirtKind.VIRTUAL }
            tallies["structors"] = structors()
        }
        if (truth.sameLayout) {
            tallies["sizes"] = sizes()
            fields(tallies)
        }
        return Scorecard(tallies, instances.mapValues { it.value.sorted() }, notes)
    }

    private fun classes(polymorphic: Boolean): Tally {
        val attribute = if (polymorphic) "polymorphic-classes" else "classes"
        val inScope = truth.scope.mapNotNull { t[it] }.filter { !polymorphic || it.vftable != null }
        val tp = inScope.count { it.id in pairs }
        val fp = candidates.filter { !polymorphic || it.vftable != null }.count { c ->
            val match = matches[c.id]
            when {
                // A class its RTTI names is real; a build of the same source elsewhere just does not have it.
                match == null && !truth.sameBinary && c.origin in NAMED -> false.also {
                    if (!polymorphic) notes += "class ${c.describe()}: not in the source"
                }

                match == null -> true.also { fp(attribute, "invented ${c.describe()}") }

                else -> false
            }
        }
        val missed = inScope.filter { it.id !in pairs }
        missed.forEach { fn(attribute, it.describe()) }
        return Tally(tp, fp, missed.size)
    }

    /** Counts the truth classes in scope that were found as one class, and the pieces split off the others. */
    private fun classSplits(): Tally {
        val found = pairs.keys.filter { it in truth.scope }
        val pieces = found.flatMap { tid ->
            splits[tid].orEmpty().onEach { fp("class-splits", "${it.describe()} of `${t[tid]?.qualifiedName}`") }
        }
        return Tally(tp = found.count { splits[it].isNullOrEmpty() }, fp = pieces.size)
    }

    /** The truth class a subject base names: through its own class's match, else by name. */
    private fun BaseRef.truthKey(): String = targetId?.let(truthOf::get)?.let { "#$it" }
        ?: truthByName[name]?.firstOrNull()?.let { "#${it.id}" }
        ?: "?$name"

    /**
     * The truth class a truth base names. The stabs sometimes name a base without its namespace and leave its id
     * out, as `Empty` for `CryptoPP::Empty`. Such a name goes to the one truth class it ends the name of.
     */
    private fun BaseRef.ownKey(): String = targetId?.let { "#$it" }
        ?: (truthByName[name] ?: truthByLeaf[name]?.takeIf { it.size == 1 })?.firstOrNull()?.let { "#${it.id}" }
        ?: "?$name"

    private val truthByLeaf by lazy {
        t.classes.flatMap { c -> leafNames(c.qualifiedName).map { it to c } }.groupBy({ it.first }, { it.second })
    }

    /** Each name [qualified] ends with after a `::` outside template arguments: `C`, then `B::C`, of `A::B::C`. */
    private fun leafNames(qualified: String): List<String> =
        qualified.nameSegments.let { segments -> (1 until segments.size).map { segments.drop(it).joinToString("::") } }

    /**
     * Whether the truth class with this key has no vtable and no functions, leaving a recovery nothing to find.
     * So has a base the truth holds no class for, since nothing names its class's functions or vtable either.
     */
    private fun String.isUnreachable() = startsWith("?") || removePrefix("#").toLongOrNull()?.let { t[it] }
        ?.let { it.vftable == null && it.functions().isEmpty() } == true

    private fun keyName(key: String) = key.removePrefix("#").toLongOrNull()?.let { t[it]?.qualifiedName } ?: key

    private fun bases(tallies: MutableMap<String, Tally>) {
        var edges = Tally()
        var access = Tally()
        var offsets = Tally()
        for ((tc, sc) in scoredPairs) {
            val claimed = sc.bases.associateBy { it.truthKey() to it.isVirtual }
            // A base with no vtable and no functions of its own gives a recovery nothing to find it by. Finding it
            // still counts, but missing it is not counted as a miss.
            val actualMap = tc.bases.associateBy { it.ownKey() to it.isVirtual }
                .filterKeys { it in claimed || !it.first.isUnreachable() }
            for (key in tc.bases.map { it.ownKey() to it.isVirtual } - actualMap.keys) {
                notes += "base `${keyName(key.first)}` of `${tc.qualifiedName}`: no vtable nor function to find it by"
            }
            edges += Tally.of(claimed.keys, actualMap.keys)
            fun edge(key: Pair<String, Boolean>) =
                "`${keyName(key.first)}`${if (key.second) " (virtual)" else ""} of `${tc.qualifiedName}`"
            (claimed.keys - actualMap.keys).forEach { fp("bases", edge(it)) }
            (actualMap.keys - claimed.keys).forEach { fn("bases", edge(it)) }
            for (key in claimed.keys intersect actualMap.keys) {
                val a = actualMap.getValue(key)
                val c = claimed.getValue(key)
                // Neither ABI's RTTI tells a protected base from a private one: only whether it is public.
                if (a.access != null) {
                    access += attribute("base-access", c.access?.publicness(), a.access.publicness()) {
                        "`${a.name}` of `${tc.qualifiedName}`"
                    }
                }
                if (truth.sameLayout && !a.isVirtual && a.offset != null) {
                    offsets += attribute("base-offsets", c.offset, a.offset) { "`${a.name}` of `${tc.qualifiedName}`" }
                }
            }
        }
        tallies["bases"] = edges
        tallies["base-access"] = access
        if (truth.sameLayout) tallies["base-offsets"] = offsets
    }

    /** Compares the [claimed] value of [name] with its [actual] one: right, wrong, or not claimed. */
    private fun <T> attribute(name: String, claimed: T?, actual: T, what: () -> String): Tally = when (claimed) {
        actual -> Tally(tp = 1)
        null -> Tally(fn = 1).also { fn(name, "${what()}: none, is $actual") }
        else -> Tally(fp = 1).also { fp(name, "${what()}: $claimed, is $actual") }
    }

    private fun vftables(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        acc + when {
            tc.vftable == null && sc.vftable == null -> Tally()

            // A dynamic class the binary has no vtable of, as gcc leaves out a class that is only ever built as a
            // base: the table its base-object structors use inside a derived class is the best a recovery has. A
            // virtual base gives a class a vptr even with no virtual functions.
            tc.vftable == null && tc.id !in truthVtableClasses &&
                (tc.functions().any { isTrulyVirtual(tc, it) } || tc.bases.any { it.isVirtual }) -> Tally()

            tc.vftable == null -> Tally(fp = 1).also { fp("vftables", "${sc.vftable} of `${tc.qualifiedName}`") }

            sc.vftable == null -> Tally(fn = 1).also { fn("vftables", "${tc.vftable} of `${tc.qualifiedName}`") }

            truth.sameBinary && sc.vftable.offset != tc.vftable.offset -> Tally(fp = 1, fn = 1).also {
                fp("vftables", "${sc.vftable} of `${tc.qualifiedName}`: is ${tc.vftable}")
                fn("vftables", "${tc.vftable} of `${tc.qualifiedName}`: claimed ${sc.vftable}")
            }

            else -> Tally(tp = 1)
        }
    }

    private fun abstract(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        acc + when {
            tc.isAbstract && sc.isAbstract -> Tally(tp = 1)
            sc.isAbstract -> Tally(fp = 1).also { fp("abstract", "`${tc.qualifiedName}`") }
            tc.isAbstract -> Tally(fn = 1).also { fn("abstract", "`${tc.qualifiedName}`") }
            else -> Tally()
        }
    }

    /**
     * Compares, by address, the functions that each class and its splits claim with the truth's, keeping only
     * those [pick] selects. A function claimed by an unmatched class is a false positive too, since it belongs
     * to no class that the recovery found.
     */
    private fun methods(name: String, actualPick: (ClassView, Member) -> Boolean, pick: (Member) -> Boolean): Tally {
        var total = Tally()
        for ((tc, sc) in scoredPairs) {
            val claimed = (listOf(sc) + splits[tc.id].orEmpty()).flatMap { it.functions() }
                .filter(pick).map { it.at }.filter { it !in truthThunks }
            val actual = tc.functions().filter { actualPick(tc, it) }.associateBy { it.at }
            total += Tally.of(claimed, actual.keys)
            for (at in claimed.toSet() - actual.keys) {
                val owner = truthFunctionOwner[at]?.let { t[it]?.qualifiedName }
                val whose = owner?.let { ": is `$it`'s" } ?: ": no method"
                fp(name, "${"%x".format(at)} of `${tc.qualifiedName}`$whose")
            }
            (actual.keys - claimed.toSet()).forEach {
                fn(name, "`${tc.qualifiedName}::${actual.getValue(it).name}` ${"%x".format(it)}")
            }
        }
        // An unscored library class's functions are neither: only a class matched to nothing claims falsely.
        val strays = candidates.filter { it.id !in matches }.flatMap { c ->
            c.functions().filter(pick).filter { it.at !in truthThunks }.map { c to it }
        }
        for ((c, m) in strays) {
            val owner = truthFunctionOwner[m.at]?.let { t[it]?.qualifiedName }
            fp(name, "${"%x".format(m.at)} of unmatched `${c.qualifiedName}`" + (owner?.let { ": is `$it`'s" } ?: ""))
        }
        return total + Tally(fp = strays.size)
    }

    /**
     * Whether a truth member is virtual. Some stabs mark only the deleting variant of a virtual destructor as
     * virtual, and leave the complete-object variant plain even though an Itanium vtable holds it too.
     *
     * No vtable holds the base-object destructor. From gcc 5 on, an abstract class's own vtable doesn't hold its
     * destructors either, because it leaves those slots null. A recovery can't tell that a destructor is virtual
     * when no vtable holds it, so such a destructor doesn't count as a virtual method.
     */
    private fun isTrulyVirtual(cls: ClassView, m: Member): Boolean {
        val marked = m.attrs?.virt == VirtKind.VIRTUAL || (
            m.name.startsWith("~") && m.variants.any { it != ItaniumStructor.BASE_DTOR } &&
                cls.functions().any { it.name == m.name && it.attrs?.virt == VirtKind.VIRTUAL }
            )
        val unslotted = vtableSlots != null && m.variants.isNotEmpty() && m.name.startsWith("~") &&
            cls.id in truthVtableClasses && m.at !in vtableSlots
        return marked && !unslotted
    }

    /** A constructor's or destructor's name: the class's own, less a template's arguments, which g++ leaves off. */
    private fun ClassView.isStructorName(member: String) = member.removePrefix("~").substringBefore('<') ==
        name.substringBefore('<')

    private fun ClassView.isStructor(m: Member) =
        isStructorName(m.name) || m.variants.isNotEmpty() || m.msvcStructor != null

    private fun structors(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        val claimed = sc.functions().filter { sc.isStructor(it) }.map { it.at }.filter {
            it !in truthThunks
        }
        val actual = tc.functions().filter { tc.isStructorName(it.name) }.map { it.at }
        (claimed.toSet() - actual.toSet()).forEach { fp("structors", "${"%x".format(it)} of `${tc.qualifiedName}`") }
        (actual.toSet() - claimed.toSet()).forEach { fn("structors", "${"%x".format(it)} of `${tc.qualifiedName}`") }
        acc + Tally.of(claimed, actual)
    }

    private fun sizes(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        acc + (tc.size?.let { attribute("sizes", sc.size, it) { "`${tc.qualifiedName}`" } } ?: Tally())
    }

    /** Each struct's leaf fields by offset; then, of the offsets both have, whether the sizes agree. */
    private fun fields(tallies: MutableMap<String, Tally>) {
        var offsets = Tally()
        var sizes = Tally()
        for ((tc, sc) in scoredPairs) {
            val actual = truth.snapshot.fields[tc.id] ?: continue
            val claimed = subject.fields[sc.id].orEmpty()
            val tally = Tally.of(claimed.keys, actual.keys)
            val sized = (claimed.keys intersect actual.keys).partition { claimed[it] == actual[it] }
            (claimed.keys - actual.keys).forEach { fp("fields", "`${tc.qualifiedName}`+$it:${claimed[it]}") }
            (actual.keys - claimed.keys).forEach { fn("fields", "`${tc.qualifiedName}`+$it:${actual[it]}") }
            sized.second.forEach { fp("field-sizes", "`${tc.qualifiedName}`+$it: ${claimed[it]}, is ${actual[it]}") }
            offsets += tally
            sizes += Tally(tp = sized.first.size, fp = sized.second.size)
        }
        tallies["fields"] = offsets
        tallies["field-sizes"] = sizes
    }
}
