package ghicpp.score

import ghicpp.Access
import ghicpp.MemberAttrs
import ghicpp.VirtKind
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.BaseRef
import ghicpp.hierarchy.ClassHierarchy.ClassView
import ghicpp.hierarchy.ClassHierarchy.Member
import ghicpp.hierarchy.ClassHierarchy.MemberKind
import ghicpp.hierarchy.ClassHierarchy.Origin
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class ScorerTest {
    private fun fn(at: Long, name: String, virtual: Boolean = false) = Member(
        name,
        "%08x".format(at),
        MemberKind.FUNCTION,
        attrs = MemberAttrs(virt = VirtKind.VIRTUAL.takeIf { virtual }),
    )

    private fun cls(
        id: Long,
        name: String,
        origin: Origin,
        vftable: Long? = null,
        members: List<Member> = emptyList(),
        bases: List<BaseRef> = emptyList(),
        abstract: Boolean = false,
        size: Long? = null,
    ) = ClassView(
        id, listOf(name), origin,
        vftable?.let {
            "%08x".format(it)
        },
        null, null, null, null, abstract, members, bases, size,
    )

    private fun base(name: String, id: Long?, virtual: Boolean = false, offset: Long? = 0) =
        BaseRef(name, id, virtual, Access.PUBLIC, offset)

    // Shape is abstract; Circle derives from it; Point is a plain struct with a method.
    private val truth = ClassHierarchy(
        listOf(
            cls(
                1,
                "Shape",
                Origin.STABS,
                0x100,
                listOf(fn(0x10, "~Shape", true), fn(0x14, "name", true)),
                abstract = true,
                size = 12,
            ),
            cls(
                2,
                "Circle",
                Origin.STABS,
                0x120,
                listOf(fn(0x20, "Circle"), fn(0x24, "area", true)),
                listOf(base("Shape", 1)),
                size = 20,
            ),
            cls(3, "Point", Origin.STABS, members = listOf(fn(0x30, "mid"))),
            cls(4, "Empty", Origin.STABS),
        ),
    )
    private val truthSnapshot = Snapshot(
        "truth",
        truth,
        mapOf(2L to mapOf(0L to 4, 12L to 8)),
        listOf(VtableExtent(0x100, 0x110, 1), VtableExtent(0x120, 0x130, 2)),
    )

    private fun score(subject: ClassHierarchy, fields: Map<Long, Map<Long, Int>> = emptyMap()) = Scorer(
        Truth(truthSnapshot, Truth.describedScope(truth), sameBinary = true, sameLayout = true),
        Snapshot("subject", subject, fields),
    ).score()

    @Test
    fun `the truth's scope is what it describes and has a vtable or a function for`() {
        Truth.describedScope(truth) mustBe setOf(1L, 2L, 3L)
    }

    @Test
    fun `a class recovered by its vtable alone matches, and one off a table no class owns is invented`() {
        val subject = ClassHierarchy(
            listOf(
                cls(
                    10,
                    "Klass_100",
                    Origin.INFERRED,
                    0x100,
                    listOf(fn(0x10, "~Klass_100", true)),
                    abstract = true,
                    size = 12,
                ),
                cls(
                    11,
                    "Klass_120",
                    Origin.INFERRED,
                    0x120,
                    listOf(fn(0x24, "vfunction1", true), fn(0x30, "f")),
                    listOf(base("Klass_100", 10)),
                ),
                cls(12, "Klass_200", Origin.INFERRED, 0x200, listOf(fn(0x40, "vfunction1", true))),
            ),
        )
        val card = score(subject, mapOf(11L to mapOf(0L to 4, 12L to 4)))
        card.tallies["classes"] mustBe Tally(tp = 2, fp = 1, fn = 1)
        card.tallies["polymorphic-classes"] mustBe Tally(tp = 2, fp = 1, fn = 0)
        card.tallies["bases"] mustBe Tally(tp = 1)
        card.tallies["abstract"] mustBe Tally(tp = 1)
        // Circle's 0x30 is Point's; Klass_200's 0x40 belongs to no class it was matched to.
        card.tallies["methods"] mustBe Tally(tp = 2, fp = 2, fn = 2)
        card.tallies["virtual-methods"] mustBe Tally(tp = 2, fp = 1, fn = 1)
        card.tallies["structors"] mustBe Tally(tp = 1, fp = 0, fn = 1)
        card.tallies["sizes"] mustBe Tally(tp = 1, fn = 1)
        card.tallies["fields"] mustBe Tally(tp = 2)
        card.tallies["field-sizes"] mustBe Tally(tp = 1, fp = 1)
    }

    @Test
    fun `a second class off the same truth class is a duplicate, and a wrong base is false and missed`() {
        val subject = ClassHierarchy(
            listOf(
                cls(10, "Shape", Origin.ITANIUM_RTTI, 0x100),
                cls(11, "Circle", Origin.ITANIUM_RTTI, 0x120, bases = listOf(base("Shape", 10, virtual = true))),
                cls(12, "Klass_124", Origin.INFERRED, 0x124),
            ),
        )
        val card = score(subject)
        card.tallies["classes"] mustBe Tally(tp = 2, fp = 1, fn = 1)
        card.tallies["bases"] mustBe Tally(tp = 0, fp = 1, fn = 1)
        card.tallies["abstract"] mustBe Tally(fn = 1)
        card.findings.any { it.startsWith("duplicate class `Klass_124`") } mustBe true
    }

    @Test
    fun `counters are each attribute's three tallies`() {
        Scorecard(mapOf("classes" to Tally(3, 1, 2)), emptyList()).counters() mustBe
            mapOf("classes-tp" to 3L, "classes-fp" to 1L, "classes-fn" to 2L)
    }
}
