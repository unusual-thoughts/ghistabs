@file:UsesShims

package ghicpp.abi

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidrakt.*
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class SlotDefinitionTest {
    @Test
    fun `a slot is never noreturn, though the function it was made from is`() {
        val throwing = FunctionDefinitionDataType("fail").apply {
            setNoReturn(true)
            returnType = IntegerDataType.dataType
            setArguments(ParameterDefinitionImpl("code", IntegerDataType.dataType, null))
        }
        val slot = slotDefinition(CategoryPath("/vftables"), "fail", throwing, null)
        slot.hasNoReturn() mustBe false
        // Everything else is the function's.
        slot.returnType.isEquivalent(IntegerDataType.dataType) mustBe true
        slot.arguments.map { it.name } mustBe listOf("code")
    }
}
