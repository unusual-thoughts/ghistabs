package ghistabs.integration

import ghidra.program.model.data.Composite
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.importer.ImportOptions.Companion.markStabsDone
import ghistabs.test.defaultContext
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * Importing a program that already carries the import — `Tools > Stabs > Re-import`, or the CLI given
 * a `.gzf` — leaves it as the first import did. Three ways it did not: every struct, union and enum
 * forked a `.conflict` for its empty cycle-break stub, which every use then pointed at; a `char`
 * register local came back as `c_reg_1` beside the `c_reg` Ghidra had narrowed to `CL`; and a swept
 * vftable slot, typed off a target the first import had since typed, forked one too.
 */
@Tag("integration")
class ReimportIntegrationTest : FeatureFixtureTest() {
    private fun snapshot() = buildMap {
        for (dt in program.dataTypeManager.allDataTypes) {
            put(dt.pathName, (dt as? Composite)?.components?.joinToString { "${it.fieldName}:${it.dataType.pathName}" })
        }
        for (func in program.functionManager.getFunctions(true)) {
            put(
                func.getName(true),
                func.getSignature(true).prototypeString +
                    func.allVariables.joinToString { "${it.name}@${it.variableStorage}" },
            )
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["hello_elf_gcc272", "hello_elf_gcc295", "hello_elf_gcc8", "hello_gcc345.exe"])
    fun `importing again changes nothing`(fixture: String) {
        load(fixture)
        val first = snapshot()
        program.markStabsDone(false)
        program.defaultContext().import()
        val again = snapshot()
        (again.keys - first.keys) mustBe emptySet()
        (first.keys - again.keys) mustBe emptySet()
        first.filter { (k, v) -> again[k] != v }.keys mustBe emptySet()
    }
}
