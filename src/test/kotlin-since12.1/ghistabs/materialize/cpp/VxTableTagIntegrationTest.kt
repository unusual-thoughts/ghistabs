package ghistabs.materialize.cpp

import ghidra.program.model.data.Structure
import ghidra.program.model.gclass.ClassUtils
import ghistabs.integration.FeatureFixtureTest
import ghistabs.parse.TypeDecl
import ghistabs.test.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

/**
 * Every `<Class>_vftable` the import fills carries the offset tag `ClassUtils.isVTable` (12.1+)
 * recognises a table by, at the offset of the `{vfptr}` that points at it — which the stab states:
 * 0 under Itanium, after the class's own fields under gcc 2.x (`Shape`'s at +12, `Named`'s at +8).
 */
@Tag("integration")
class VxTableTagIntegrationTest : FeatureFixtureTest() {
    @ParameterizedTest
    @MethodSource("hellos")
    fun `every filled vftable is one ClassUtils recognises`(fixture: String) {
        load(fixture)
        val untagged = filledVftables().filterNot(ClassUtils::isVTable).map { "${it.pathName}: ${it.description}" }
        untagged.mustBeEmpty("vftables isVTable does not recognise")
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a vftable's tag is where the stab puts the vptr that points at it`(fixture: String) {
        load(fixture)
        val tables = filledVftables().associateBy { it.name.removeSuffix("_vftable") }
        // Circle inherits Shape's vptr, at the same offset since Shape is its base at 0.
        for ((cls, declaring) in listOf("Shape" to "Shape", "Circle" to "Shape", "Named" to "Named")) {
            val vft = tables[cls] ?: continue
            val expected = vptrOffsetBytesOf(body(declaring))?.toLong() ?: 0L
            ClassUtils.validateVtableDescriptionOffsetTag(vft.description).mustBe(expected, "${vft.name}'s tag")
        }
    }

    /**
     * `Diamond : Left, Right, Named` has two secondaries under Itanium: `Right`'s at +8, which has no
     * virtuals and so no slots, then `Named`'s at +16 with its destructor thunks. The walk has to step
     * over the first to reach the second, and the table laid there is tagged at +16, its own vptr.
     */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `a secondary behind a slotless one is laid, tagged at its own vptr`(fixture: String) {
        load(fixture)
        assumeTrue("gcc2" !in fixture, "gcc 2.x gives each secondary its own symbol; nothing to walk")
        assumeTrue(filledVftables().any { it.name == "Diamond_vftable" }, "$fixture laid no Diamond vftable")

        val secondaries = program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name.startsWith("Diamond_vftable_internal_") && it.numComponents > 0 }
            .map { ClassUtils.validateVtableDescriptionOffsetTag(it.description) }
            .toList()
        secondaries mustBe listOf(16L)
    }

    private fun filledVftables() = program.dataTypeManager.allDataTypes.asSequence()
        .filterIsInstance<Structure>()
        .filter { "ClassDataTypes" in it.categoryPath.path && it.name.endsWith("_vftable") && it.numComponents > 0 }
        .toList()

    private fun body(name: String) = artifacts.harvest.types.values
        .mapNotNull { (it.body as? TypeDecl.Aggregate)?.takeIf { _ -> it.name == name } }
        .first()

    companion object {
        @JvmStatic
        fun hellos() = FEATURES.list().orEmpty().filter { it.startsWith("hello_") }.sorted()
    }
}
