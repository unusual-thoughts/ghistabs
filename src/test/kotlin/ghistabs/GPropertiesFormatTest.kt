package ghistabs

import ghidra.framework.options.GProperties
import ghistabs.parse.Access
import ghistabs.test.*
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test

class GPropertiesFormatTest {
    @Serializable
    data class Leaf(val id: Long?, val name: String?, val flag: Boolean, val access: Access, val c: Char = 'x')

    @Serializable
    data class Tree(
        val leaves: List<Leaf>,
        val byId: Map<Long, Leaf>,
        val byAccess: Map<Access, List<Int>>,
        val nested: Leaf?,
        val defaulted: Double = 1.5,
    )

    /** Through XML too, as a custom option is stored. */
    private inline fun <reified T> T.roundTrip(): T {
        val props = GProperties("test").also { GPropertiesFormat.encode(this, it) }
        return GPropertiesFormat.decode<T>(GProperties(props.saveToXml()))
    }

    private val leaves = (0..11).map { i ->
        Leaf(i.toLong().takeIf { i % 3 != 0 }, "n<$i>&".takeIf { i % 2 == 0 }, i % 2 == 1, Access.entries[i % 3])
    }

    @Test
    fun `values read back as written, lists in order, nulls and nested structures included`() {
        val tree =
            Tree(
                leaves,
                leaves.associateBy {
                    it.hashCode().toLong()
                },
                mapOf(Access.PRIVATE to listOf(3, 1, 2)),
                leaves[1],
            )
        tree.roundTrip() mustBe tree
        Tree(emptyList(), emptyMap(), emptyMap(), null, 2.0).let { it.roundTrip() mustBe it }
    }

    @Test
    fun `a property with a default falls back to it when absent`() {
        val props = GProperties("test").also {
            GPropertiesFormat.encode(Tree(emptyList(), emptyMap(), emptyMap(), null, 3.0), it)
        }
        props.remove("defaulted")
        GPropertiesFormat.decode<Tree>(props).defaulted mustBe 1.5
    }
}
