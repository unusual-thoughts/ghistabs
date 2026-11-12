package ghicpp.abi.itanium

import ghicpp.ClassNaming
import ghicpp.ClassStructsFixtureTest
import ghicpp.VfptrModel
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

/**
 * [ItaniumClassStructsIntegrationTest]'s binary with *Itanium RTTI classes* set to [VfptrModel.INHERITED]: a
 * class keeps each base whole, `{vfptr}` and all, and adds a `{vfptr}` of its own only where no base holds
 * its vptr.
 */
class ItaniumInheritedVfptrIntegrationTest :
    ClassStructsFixtureTest("hello_elf_gcc12_stripped", compiler = "gcc", VfptrModel.INHERITED) {
    @Test
    fun `a base holding a vptr is embedded whole`() {
        program.layout("Both") mustBe listOf(
            0 to "_base_Up: Up",
            8 to "_base_Down: Down",
            16 to "Both_data: Both_data",
            20 to "_vbase_Core: Core",
        )
    }

    @Test
    fun `no base is split into its fields`() {
        val split = program.dataTypeManager.allStructures.asSequence()
            .filter { it.categoryPath.path.startsWith("/ClassDataTypes/") && ClassNaming.FIELDS in it.name }
            .map { it.pathName }
            .toList()
        split mustBe emptyList()
    }
}
