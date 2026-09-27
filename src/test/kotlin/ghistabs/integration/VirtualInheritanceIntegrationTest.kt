package ghistabs.integration

import ghidra.program.model.data.Structure
import ghidra.program.model.gclass.ClassUtils
import ghistabs.parse.TypeDecl
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

/**
 * `features/hello.cc`'s diamond, on every compiler that built it:
 *
 * ```
 * struct Base { int id; };
 * struct Left : virtual Base { int l; };
 * struct Right : virtual Base { int r; };
 * struct Diamond : Left, Right, Named { int d; };
 * ```
 *
 * No inheritance line says where a virtual base is: gcc ≥ 3.0 writes a vtable offset (`!1,12-96,`),
 * gcc 2.x writes 0 and reaches the base through a `_vb$` pointer. `Base` belongs after the non-virtual
 * data, once, in the complete object, and a class embedded as a base brings only its non-virtual part:
 * `Left` and `Right` are 8 bytes inside `Diamond`, not the 12 they are on their own.
 */
@Tag("integration")
class VirtualInheritanceIntegrationTest : FeatureFixtureTest() {
    @ParameterizedTest
    @MethodSource("hellos")
    fun `a virtual base is laid once, after the non-virtual data`(fixture: String) {
        load(fixture)

        for (name in listOf("Left", "Right")) {
            val cls = struct(name)
            cls.vbaseAt() mustBe 8
            cls.length mustBe 12
            if ("gcc2" in fixture) {
                cls.definedComponents.any { it.fieldName.orEmpty().startsWith("_vb$") }
                    .mustBeTrue("$name should keep the `_vb$` pointer gcc 2.x reaches Base through")
            }
        }

        val diamond = struct("Diamond")
        diamond.vbaseAt() mustBe 32
        diamond.length mustBe 36
        diamond.undefinedBytes().mustBeEmpty("Diamond bytes no component covers")
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a class embedded as a base is its self-base, filed where Ghidra's PDB importer files one`(fixture: String) {
        load(fixture)
        val diamond = struct("Diamond")

        for ((name, at) in listOf("Left" to 0, "Right" to 8)) {
            val cls = struct(name)
            val path = ClassUtils.getBaseClassDataTypePath(cls)
            val selfBase = program.dataTypeManager.getDataType(path).mustBeA<Structure>("$name's self-base at $path")
            selfBase.length mustBe 8
            selfBase.vbaseAt() mustBe null

            // The self-base whole, or under SPLIT_BASE its fields around Diamond's own {vfptr}.
            diamond.definedComponents
                .filter { it.offset in at..<at + selfBase.length }
                .any { it.dataType === selfBase || it.dataType.categoryPath == selfBase.categoryPath }
                .mustBeTrue("Diamond +$at should hold $name's non-virtual part")
        }
    }

    /** The one struct the harvest's definition of [name] materialized. */
    private fun struct(name: String): Structure = artifacts.harvest.types.values
        .filter { it.name == name && it.body is TypeDecl.Aggregate }
        .mapNotNull { artifacts.registry.dataTypeFor(it.id) as? Structure }
        .distinctBy { it.pathName }
        .single()

    private fun Structure.vbaseAt() = definedComponents.singleOrNull { it.dataType.name == "Base" }?.offset

    private fun Structure.undefinedBytes() = (0 until length).filter { b ->
        definedComponents.none { b in it.offset until it.offset + it.length }
    }

    companion object {
        @JvmStatic
        fun hellos() = FEATURES.list().orEmpty().filter { it.startsWith("hello_") }.sorted()
    }
}
