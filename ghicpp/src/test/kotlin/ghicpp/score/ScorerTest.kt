package ghicpp.score

import ghicpp.Access
import ghicpp.MemberAttrs
import ghicpp.VirtKind
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.*
import ghidrakt.DetachedAddresses
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class ScorerTest {
    private fun fn(at: Long, name: String, virtual: Boolean = false) = Member(
        name,
        DetachedAddresses.at(at),
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
        vftable?.let { DetachedAddresses.at(it) },
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

    /** Each `-fp` and `-fn` counter has as many instances as it counts. */
    private fun Scorecard.mustListEveryMiss() {
        for ((name, t) in tallies) {
            (name to instances["$name-fp"].orEmpty().size) mustBe (name to t.fp)
            (name to instances["$name-fn"].orEmpty().size) mustBe (name to t.fn)
        }
    }

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
        card.instanceLines() mustBe listOf(
            "classes-fn `Point` (stabs)",
            "classes-fp invented `Klass_200` (inferred, vftable 00000200)",
            "field-sizes-fp `Circle`+12: 4, is 8",
            "methods-fn `Circle::Circle` 20",
            "methods-fn `Shape::name` 14",
            "methods-fp 30 of `Circle`: is `Point`'s",
            "methods-fp 40 of unmatched `Klass_200`",
            "polymorphic-classes-fp invented `Klass_200` (inferred, vftable 00000200)",
            "sizes-fn `Circle`: none, is 20",
            "structors-fn 20 of `Circle`",
            "virtual-methods-fn `Shape::name` 14",
            "virtual-methods-fp 40 of unmatched `Klass_200`",
        )
        card.mustListEveryMiss()
    }

    @Test
    fun `a second class off the same truth class is a split, and a wrong base is false and missed`() {
        val subject = ClassHierarchy(
            listOf(
                cls(10, "Shape", Origin.ITANIUM_RTTI, 0x100),
                cls(11, "Circle", Origin.ITANIUM_RTTI, 0x120, bases = listOf(base("Shape", 10, virtual = true))),
                cls(12, "Klass_124", Origin.INFERRED, 0x124),
            ),
        )
        val card = score(subject)
        card.tallies["classes"] mustBe Tally(tp = 2, fp = 0, fn = 1)
        card.tallies["class-splits"] mustBe Tally(tp = 1, fp = 1)
        card.tallies["bases"] mustBe Tally(tp = 0, fp = 1, fn = 1)
        card.tallies["abstract"] mustBe Tally(fn = 1)
        card.instances["classes-fp"] mustBe null
        card.instances["class-splits-fp"] mustBe listOf("`Klass_124` (inferred, vftable 00000124) of `Circle`")
        card.instances["bases-fp"] mustBe listOf("`Shape` (virtual) of `Circle`")
        card.instances["bases-fn"] mustBe listOf("`Shape` of `Circle`")
        card.mustListEveryMiss()
    }

    @Test
    fun `a class only named, with no vtable or function, stands for its truth class only when no other does`() {
        val subject = ClassHierarchy(
            listOf(
                cls(
                    10,
                    "Shape",
                    Origin.NAMESPACE,
                    members = listOf(Member("RTTI_Type_Descriptor", DetachedAddresses.at(0x500), MemberKind.ABI)),
                ),
                cls(11, "Klass_100", Origin.INFERRED, 0x100, abstract = true),
                cls(12, "Klass_120", Origin.INFERRED, 0x120, bases = listOf(base("Klass_100", 11))),
            ),
        )
        val card = score(subject)
        card.tallies["vftables"] mustBe Tally(tp = 2)
        card.tallies["bases"] mustBe Tally(tp = 1)
        card.tallies["abstract"] mustBe Tally(tp = 1)
        card.instances["class-splits-fp"] mustBe listOf("`Shape` (namespace) of `Shape`")
        card.mustListEveryMiss()
    }

    @Test
    fun `a split's functions count for the class it is a piece of`() {
        val subject = ClassHierarchy(
            listOf(
                cls(10, "NPKlass_20", Origin.INFERRED, members = listOf(fn(0x20, "NPKlass_20"))),
                cls(11, "NPKlass_24", Origin.INFERRED, members = listOf(fn(0x24, "NPKlass_24"))),
            ),
        )
        val card = score(subject)
        card.tallies["classes"] mustBe Tally(tp = 1, fp = 0, fn = 2)
        card.tallies["class-splits"] mustBe Tally(tp = 0, fp = 1)
        card.tallies["methods"] mustBe Tally(tp = 2, fp = 0, fn = 0)
        card.mustListEveryMiss()
    }

    @Test
    fun `a class holding one function of another's goes by its structor`() {
        val subject = ClassHierarchy(
            listOf(cls(10, "NPKlass_20", Origin.INFERRED, members = listOf(fn(0x20, "NPKlass_20"), fn(0x30, "f")))),
        )
        val card = score(subject)
        card.tallies["classes"] mustBe Tally(tp = 1, fp = 0, fn = 2)
        card.instances["methods-fp"] mustBe listOf("30 of `Circle`: is `Point`'s")
        card.mustListEveryMiss()
    }

    @Test
    fun `counters are each attribute's three tallies`() {
        Scorecard(mapOf("classes" to Tally(3, 1, 2))).counters() mustBe
            mapOf("classes-tp" to 3L, "classes-fp" to 1L, "classes-fn" to 2L)
    }
}
