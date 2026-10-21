package ghistabs.probe

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.data.PointerDataType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.dataAt
import ghistabs.memBuffer
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import ghistabs.withProgram
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

@Tag("probe")
class PseudoDataStringProbe : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun runProbe() {
        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        val fixture = File("src/test/resources/binaries/xmltest_gcc421.exe")
        withProgram(fixture, log = log, monitor = monitor) { program ->
            try {
                val dtm = program.dataTypeManager
                val buf = program.memBuffer()

                fun pointerData(addr: Address? = null) = buf.dataAt(PointerDataType(dtm), addr)
                fun isData(addr: Address) =
                    program.memory.getBlock(addr)?.let { it.isInitialized && !it.isExecute } == true

                println("PROUT CACA")
                val sitesByTarget: Map<Address, List<Address>> by lazy {
                    buildMap<Address, MutableList<Address>> {
                        for (b in program.memory.blocks.filter {
                            it.isInitialized && !it.isExecute
                        }) {
                            buf.setPosition(b.start)
                            while (buf.address in b.addressRange) {
                                val data = pointerData() ?: break
                                if (data.value !is Address) {
                                    println("BAD $data")
                                }

                                (data.value as? Address)?.takeIf { isData(it) }?.let {
                                    getOrPut(it) { mutableListOf() }.add(data.address)
                                }
                            }
                        }
                    }
                }
                // for ((k, v) in sitesByTarget) {
                //    println("$k: $v")
                // }
            } catch (e: Exception) {
                println("SHIT $e")
            }
        }
    }
}
