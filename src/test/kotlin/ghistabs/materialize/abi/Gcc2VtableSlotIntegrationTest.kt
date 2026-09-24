package ghistabs.materialize.abi

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.VoidDataType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.harvest.ProgramAddressResolver
import ghistabs.test.mustBe
import ghistabs.test.mustNotBeNull
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * PR #11 review flagged `vtableSlotTargets` as reading a gcc 2.x record's reserved header word as
 * though it were the first virtual's function pointer. It doesn't: [Vtable.vtableShape] already
 * advances `addressPoint` past the header for a [CxxAbi.vptrAtRecordStart] ABI (the same 2-pointer
 * width [Itanium.vtablePrefixBytes] computes, which [Gcc2Abi.headerBytes] independently arrives at
 * too — see its doc). This builds a minimal record of each gcc 2.x entry shape by hand — no thunks
 * (bare pfn) and no-thunk (`{delta,index,pfn}`) — and checks the first slot [vtableSlotTargets]
 * reads back is the first real function, not the reserved header reinterpreted as one.
 */
@Tag("integration")
class Gcc2VtableSlotIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun thunkTableSkipsTheTwoWordHeader() = checkFirstTwoSlots(Gcc2Thunks) { addr -> intLE(addr) }

    @Test
    fun plainTableSkipsTheHeaderAndReadsPfnAtItsOffset() = checkFirstTwoSlots(Gcc2Plain) { addr ->
        byteArrayOf(0, 0, 0, 0) + intLE(addr) // {delta, index}=0, then pfn
    }

    private fun intLE(v: Int) = byteArrayOf(
        v.toByte(),
        (v shr 8).toByte(),
        (v shr 16).toByte(),
        (v shr 24).toByte(),
    )

    private fun checkFirstTwoSlots(abi: Gcc2Abi, entryFor: (Int) -> ByteArray) {
        val builder = ProgramBuilder("gcc2-vtable-$abi", ProgramBuilder._X86)
        try {
            val ztvAddr = 0x401000
            val func0Addr = 0x402000
            val func1Addr = 0x402100

            val code = builder.createMemory(".text", "0x${func0Addr.toString(16)}", 0x200)
            builder.setExecute(code, true)
            builder.createEmptyFunction("firstVirtual", "0x${func0Addr.toString(16)}", 1, VoidDataType.dataType)
            builder.createEmptyFunction("secondVirtual", "0x${func1Addr.toString(16)}", 1, VoidDataType.dataType)

            // header, then the two real entries in this ABI's own shape.
            val record = ByteArray(abi.headerBytes(4).toInt()) + entryFor(func0Addr) + entryFor(func1Addr)
            builder.createMemory(".data", "0x${ztvAddr.toString(16)}", record.size)
            builder.setBytes("0x${ztvAddr.toString(16)}", record)

            val program = builder.program
            val resolver = ProgramAddressResolver(program)
            val ztv = program.addressFactory.defaultAddressSpace.getAddress(ztvAddr.toLong())

            val shape = program.vtableShape(ztv, resolver, abi)
            shape.addressPoint.mustBe(
                ztv.add(abi.headerBytes(4)),
                "addressPoint should land right after the reserved header",
            )

            val targets = program.vtableSlotTargets(shape.addressPoint, resolver, abi)
            targets.size.mustBe(2, "expected exactly the two real slots, header excluded")

            val firstFunc = program.functionManager.getFunctionAt(targets[0])
            firstFunc.mustNotBeNull("no Function at the first recovered target")
            firstFunc!!.name.mustBe(
                "firstVirtual",
                "vtableSlotTargets()[0] should be the first declared virtual, not the header",
            )
            program.functionManager.getFunctionAt(targets[1])?.name.mustBe("secondVirtual")
        } finally {
            builder.dispose()
        }
    }
}
