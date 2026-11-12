package ghicpp.score

import ghicpp.VirtKind
import ghicpp.abi.itanium.ItaniumStructor
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.ClassView
import ghicpp.hierarchy.ClassHierarchy.MemberKind
import ghicpp.hierarchy.ClassHierarchy.Origin

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

/** One recovery scored against its [Truth]: a [Tally] per attribute, and what each false one was. */
data class Scorecard(val tallies: Map<String, Tally>, val findings: List<String>) {
    /** The tallies as baseline counters: `<attribute>-tp`, `-fp`, `-fn`. */
    fun counters(): Map<String, Long> = tallies.flatMap { (name, t) ->
        listOf("$name-tp" to t.tp.toLong(), "$name-fp" to t.fp.toLong(), "$name-fn" to t.fn.toLong())
    }.toMap()

    fun markdown(title: String): String = buildString {
        appendLine("# $title")
        appendLine()
        appendLine("| attribute | TP | FP | FN | precision | recall |")
        appendLine("| --- | ---: | ---: | ---: | ---: | ---: |")
        for ((name, t) in tallies) {
            appendLine("| $name | ${t.tp} | ${t.fp} | ${t.fn} | ${t.precision.pct()} | ${t.recall.pct()} |")
        }
        if (findings.isNotEmpty()) {
            appendLine()
            appendLine("## False positives and negatives")
            appendLine()
            findings.forEach { appendLine("- $it") }
        }
    }

    private fun Double?.pct() = this?.let { "%.1f%%".format(it * 100) } ?: "–"

    companion object {
        /** The order attributes are reported in, and the ones a truth may not be able to score. */
        val ATTRIBUTES = listOf(
            "classes", "polymorphic-classes", "bases", "base-access", "base-offsets", "vftables", "abstract",
            "methods", "virtual-methods", "structors", "sizes", "fields", "field-sizes",
        )
    }
}

/** A class's own functions: not a thunk nor an import. */
private fun ClassView.functions() = members.filter { it.kind == MemberKind.FUNCTION && it.library == null }

private fun address(text: String) = text.substringAfter(':').toLong(16)

private fun ghicpp.Access.publicness() = if (this == ghicpp.Access.PUBLIC) "public" else "non-public"

/** Where a class's name comes from the binary: its RTTI or a symbol's namespace. */
private val NAMED = setOf(Origin.MSVC_RTTI, Origin.ITANIUM_RTTI, Origin.SWEPT_RTTI, Origin.NAMESPACE)

/**
 * Scores [subject], what a recovery from a bare binary made of its classes, against [truth].
 *
 * Each subject class is matched to a truth class by its qualified name, else by the vtable it labels,
 * else by the truth class most of its functions belong to. A subject class with no match is a false
 * class; one matched to a class the truth already has a better match for, a duplicate, is false too;
 * one matched to a truth class out of [Truth.scope] (a library's, its vtable known but not described) is
 * left unscored. Every other attribute is scored over the matched pairs in scope, the truth class's bases,
 * vtable, members and layout against the subject's: by address where [Truth.sameBinary], by offset where
 * [Truth.sameLayout], and not at all where the truth cannot tell.
 */
class Scorer(private val truth: Truth, private val subject: Snapshot) {
    private val t = truth.hierarchy
    private val s = subject.hierarchy
    private val findings = mutableListOf<String>()

    private val truthByName = t.classes.groupBy { it.qualifiedName }
    private val truthFunctionOwner: Map<Long, Long> = t.classes
        .flatMap { c -> c.functions().map { address(it.address) to c.id } }.toMap()
    private val truthVtables = truth.snapshot.vtables.sortedBy { it.start }

    /** This-adjusting thunks: what the truth lists apart from its functions, and a recovery may well call one. */
    private val truthThunks: Set<Long> = t.classes
        .flatMap { c -> c.members.filter { it.kind == MemberKind.THUNK }.map { address(it.address) } }.toSet()

    private fun vtableOwner(at: Long): Long? =
        truthVtables.lastOrNull { it.start <= at }?.takeIf { at < it.end }?.classId

    /** The truth class [cls] stands for, and how strongly: 3 by name, 2 by its vtable, 1 by most of its functions. */
    private fun matchOf(cls: ClassView): Pair<Long, Int>? {
        truthByName[cls.qualifiedName]?.let { named ->
            return (named.firstOrNull { it.id in truth.scope } ?: named.first()).id to 3
        }
        if (!truth.sameBinary) return null
        cls.vftable?.let { vtableOwner(address(it)) }?.let { return it to 2 }
        val owners = cls.functions().mapNotNull { truthFunctionOwner[address(it.address)] }
        return owners.groupingBy { it }.eachCount().maxByOrNull { it.value }
            ?.takeIf { it.value * 2 > cls.functions().size }?.let { it.key to 1 }
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

    private fun ClassView.describe() = "`$qualifiedName` (${origin.name.lowercase()}${vftable?.let {
        ", vftable $it"
    }.orEmpty()})"

    fun score(): Scorecard {
        val tallies = linkedMapOf<String, Tally>()
        tallies["classes"] = classes(polymorphic = false)
        tallies["polymorphic-classes"] = classes(polymorphic = true)
        bases(tallies)
        // Across ABIs a class's vftables differ (MSVC gives a class whose only virtuals are its virtual base's none).
        if (truth.sameBinary) tallies["vftables"] = vftables()
        tallies["abstract"] = abstract()
        if (truth.membersKnown) {
            tallies["methods"] = methods("method", { _, _ -> true }) { true }
            tallies["virtual-methods"] =
                methods("virtual method", ::isTrulyVirtual) { it.attrs?.virt == VirtKind.VIRTUAL }
            tallies["structors"] = structors()
        }
        if (truth.sameLayout) {
            tallies["sizes"] = sizes()
            fields(tallies)
        }
        return Scorecard(tallies, findings)
    }

    private fun classes(polymorphic: Boolean): Tally {
        val inScope = truth.scope.mapNotNull { t[it] }.filter { !polymorphic || it.vftable != null }
        val tp = inScope.count { it.id in pairs }
        val fp = candidates.filter { !polymorphic || it.vftable != null }.count { c ->
            val match = matches[c.id]
            when {
                // A class its RTTI names is real; a build of the same source elsewhere just does not have it.
                match == null && !truth.sameBinary && c.origin in NAMED -> false.also {
                    if (!polymorphic) findings += "unscored class ${c.describe()}: not in the source"
                }

                match == null -> true.also { if (!polymorphic) findings += "invented class ${c.describe()}" }

                truthOf[c.id] == null -> true.also {
                    if (!polymorphic) {
                        findings +=
                            "duplicate class ${c.describe()} of `${t[match.first]?.qualifiedName}`"
                    }
                }

                else -> false
            }
        }
        val missed = inScope.filter { it.id !in pairs }
        if (!polymorphic) missed.forEach { findings += "missed class ${it.describe()}" }
        return Tally(tp, fp, missed.size)
    }

    /** The truth class a subject base names: through its own class's match, else by name. */
    private fun ClassHierarchy.BaseRef.truthKey(): String = targetId?.let(truthOf::get)?.let { "#$it" }
        ?: truthByName[name]?.firstOrNull()?.let { "#${it.id}" }
        ?: "?$name"

    private fun ClassHierarchy.BaseRef.ownKey(): String = targetId?.let { "#$it" } ?: truthByName[name]?.firstOrNull()
        ?.let { "#${it.id}" } ?: "?$name"

    private fun keyName(key: String) = key.removePrefix("#").toLongOrNull()?.let { t[it]?.qualifiedName } ?: key

    private fun bases(tallies: MutableMap<String, Tally>) {
        var edges = Tally()
        var access = Tally()
        var offsets = Tally()
        for ((tc, sc) in scoredPairs) {
            val actual = tc.bases.associateBy { it.ownKey() to it.isVirtual }
            val claimed = sc.bases.associateBy { it.truthKey() to it.isVirtual }
            edges += Tally.of(claimed.keys, actual.keys)
            (claimed.keys - actual.keys).forEach {
                findings +=
                    "false base `${keyName(it.first)}`${if (it.second) " (virtual)" else ""} of `${tc.qualifiedName}`"
            }
            (actual.keys - claimed.keys).forEach {
                findings +=
                    "missed base `${keyName(it.first)}`${if (it.second) " (virtual)" else ""} of `${tc.qualifiedName}`"
            }
            for (key in claimed.keys intersect actual.keys) {
                val a = actual.getValue(key)
                val c = claimed.getValue(key)
                // Neither ABI's RTTI tells a protected base from a private one: only whether it is public.
                val actualAccess = a.access
                if (actualAccess != null) {
                    access += attribute(c.access?.publicness(), actualAccess.publicness()) {
                        "access of base `${a.name}` of `${tc.qualifiedName}`"
                    }
                }
                if (truth.sameLayout && !a.isVirtual && a.offset != null) {
                    offsets += attribute(c.offset, a.offset) { "offset of base `${a.name}` of `${tc.qualifiedName}`" }
                }
            }
        }
        tallies["bases"] = edges
        tallies["base-access"] = access
        if (truth.sameLayout) tallies["base-offsets"] = offsets
    }

    /** One attribute's [claimed] value against its [actual] one: right, wrong, or not claimed. */
    private fun <T> attribute(claimed: T?, actual: T, what: () -> String): Tally = when (claimed) {
        actual -> Tally(tp = 1)
        null -> Tally(fn = 1).also { findings += "no ${what()}: is $actual" }
        else -> Tally(fp = 1).also { findings += "wrong ${what()}: $claimed, is $actual" }
    }

    private fun vftables(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        val truthVftable = tc.vftable
        val scoredVftable = sc.vftable
        acc + when {
            truthVftable == null && scoredVftable == null -> Tally()

            truthVftable == null -> Tally(fp = 1).also {
                findings +=
                    "false vftable $scoredVftable of `${tc.qualifiedName}`"
            }

            scoredVftable == null -> Tally(fn = 1).also {
                findings +=
                    "missed vftable $truthVftable of `${tc.qualifiedName}`"
            }

            truth.sameBinary && address(scoredVftable) != address(truthVftable) ->
                Tally(fp = 1, fn = 1).also {
                    findings +=
                        "wrong vftable $scoredVftable of `${tc.qualifiedName}`: is $truthVftable"
                }

            else -> Tally(tp = 1)
        }
    }

    private fun abstract(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        acc + when {
            tc.isAbstract && sc.isAbstract -> Tally(tp = 1)
            sc.isAbstract -> Tally(fp = 1).also { findings += "`${tc.qualifiedName}` called abstract" }
            tc.isAbstract -> Tally(fn = 1).also { findings += "`${tc.qualifiedName}` not called abstract" }
            else -> Tally()
        }
    }

    /**
     * The functions each class claims that [pick] keeps, by address, against the truth's. A function an
     * unmatched or duplicate class claims is false too: it belongs to no class the recovery found.
     */
    private fun methods(
        label: String,
        actualPick: (ClassView, ClassHierarchy.Member) -> Boolean,
        pick: (ClassHierarchy.Member) -> Boolean,
    ): Tally {
        var total = Tally()
        for ((tc, sc) in scoredPairs) {
            val claimed = sc.functions().filter(pick).map { address(it.address) }.filter { it !in truthThunks }
            val actual = tc.functions().filter { actualPick(tc, it) }.associateBy { address(it.address) }
            total += Tally.of(claimed, actual.keys)
            for (at in claimed.toSet() - actual.keys) {
                val owner = truthFunctionOwner[at]?.let { t[it]?.qualifiedName }
                findings += "false $label ${"%x".format(at)} of `${tc.qualifiedName}`" +
                    (owner?.let { ": is `$it`'s" } ?: ": no method")
            }
            (actual.keys - claimed.toSet()).forEach {
                findings +=
                    "missed $label `${tc.qualifiedName}::${actual.getValue(it).name}`"
            }
        }
        // An unscored library class's functions are neither: only a class matched to nothing claims falsely.
        val strays = candidates.filter { it.id !in truthOf }
            .sumOf { c -> c.functions().filter(pick).count { address(it.address) !in truthThunks } }
        return total + Tally(fp = strays)
    }

    /**
     * A truth member that is virtual. Some stabs mark only the deleting variant of a virtual destructor so; the
     * complete one, which an Itanium vtable holds too, comes out plain. The base-object one no vtable holds.
     */
    private fun isTrulyVirtual(cls: ClassView, m: ClassHierarchy.Member) = m.attrs?.virt == VirtKind.VIRTUAL ||
        (
            m.name.startsWith("~") && m.variants.any { it != ItaniumStructor.BASE_DTOR } &&
                cls.functions().any { it.name == m.name && it.attrs?.virt == VirtKind.VIRTUAL }
            )

    /** A constructor's or destructor's name: the class's own, less a template's arguments, which g++ leaves off. */
    private fun ClassView.isStructorName(member: String) = member.removePrefix("~").substringBefore('<') ==
        name.substringBefore('<')

    private fun ClassView.isStructor(m: ClassHierarchy.Member) =
        isStructorName(m.name) || m.variants.isNotEmpty() || m.msvcStructor != null

    private fun structors(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        val claimed = sc.functions().filter { sc.isStructor(it) }.map { address(it.address) }.filter {
            it !in
                truthThunks
        }
        val actual = tc.functions().filter {
            it.name == tc.name || it.name == "~${tc.name}"
        }.map { address(it.address) }
        (claimed.toSet() - actual.toSet()).forEach {
            findings +=
                "false structor ${"%x".format(it)} of `${tc.qualifiedName}`"
        }
        acc + Tally.of(claimed, actual)
    }

    private fun sizes(): Tally = scoredPairs.fold(Tally()) { acc, (tc, sc) ->
        acc + (tc.size?.let { attribute(sc.size, it) { "size of `${tc.qualifiedName}`" } } ?: Tally())
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
            if (tally.fp + tally.fn + sized.second.size > 0) {
                findings += "fields of `${tc.qualifiedName}`: ${tally.fp} false, ${tally.fn} missed, " +
                    "${sized.second.size} mis-sized (offset:size; claimed ${claimed.render()}; is ${actual.render()})"
            }
            offsets += tally
            sizes += Tally(tp = sized.first.size, fp = sized.second.size)
        }
        tallies["fields"] = offsets
        tallies["field-sizes"] = sizes
    }

    private fun Map<Long, Int>.render() = entries.joinToString(" ") { "${it.key}:${it.value}" }
}
