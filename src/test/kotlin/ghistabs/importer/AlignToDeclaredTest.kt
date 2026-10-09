package ghistabs.importer

import ghidra.program.model.data.*
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** Pure unit tests for [alignToDeclared], on real Ghidra DataTypes as [DemanglerReplaceCoreTest] does. */
class AlignToDeclaredTest {
    private val uint = UnsignedIntegerDataType.dataType
    private val int = IntegerDataType.dataType
    private val voidPtr = PointerDataType(VoidDataType.dataType, 4)
    private val charPtr = PointerDataType(CharDataType.dataType, 4)
    private val double = DoubleDataType.dataType
    private val nameValuePairs = StructureDataType("NameValuePairs", 0).apply { add(int, "i", null) }

    private fun align(stabs: List<DataType?>, declared: List<DataType?>) =
        alignToDeclared(stabs, declared.map { lazyOf(it) })

    @Test
    fun anUnnamedParameterAtTheHeadIsPlacedThere() {
        // operator new(size_t, void* __p)
        align(listOf(voidPtr), listOf(uint, voidPtr)) mustBe listOf(null, 0)
    }

    @Test
    fun anUnnamedParameterInTheMiddleIsPlacedThere() {
        // f(int a, const Foo&, char* c)
        align(listOf(int, charPtr), listOf(int, PointerDataType(nameValuePairs, 4), charPtr)) mustBe
            listOf(0, null, 1)
    }

    @Test
    fun aTypedefAgreesWithWhatItNames() {
        val sizeT = TypedefDataType("size_t", uint)
        align(listOf(double, sizeT), listOf(sizeT, double, uint)) mustBe listOf(null, 0, 1)
    }

    @Test
    fun theGapGoesOnTheTailWhenNothingTellsTheSlotsApart() {
        // HMAC_Base::UncheckedSetKey(const byte*, unsigned int, const NameValuePairs&)
        val bytePtr = PointerDataType(ByteDataType.dataType, 4)
        val nvpRef = PointerDataType(nameValuePairs, 4)
        align(listOf(bytePtr, uint), listOf(bytePtr, uint, nvpRef)) mustBe listOf(0, 1, null)
        align(listOf(null), listOf(int, int)) mustBe listOf(0, null)
    }

    @Test
    fun equalCountsLineUpAndTooFewSlotsDoNot() {
        align(listOf(null, int), listOf(double, double)) mustBe listOf(0, 1)
        align(listOf(int, int), listOf(int)) mustBe null
    }
}
