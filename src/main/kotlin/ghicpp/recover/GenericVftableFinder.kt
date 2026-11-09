package ghicpp.recover

import ghicpp.ClassNaming
import ghicpp.abi.importedFunction
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.*

fun Program.findPointers() = cursorAt().run {
    sequence {
        for (b in memory.blocks.filter {
            it.isInitialized && !it.isExecute &&
                it.start.addressSpace == addressFactory.defaultAddressSpace
        }) {
            seek(b.start.alignTo(defaultPointerSize.toLong()))
            while (address in b) {
                yield(address to (nextPointer() ?: break))
            }
        }
    }
}
data class Pointer(val src: Address, val dst: Address, val refs: List<Address>)

private fun Program.pointerOf(src: Address, dst: Address) = Pointer(
    src,
    dst,
    referenceManager.getReferencesTo(src).filter {
        it.referenceType.isRead && isCode(it.fromAddress)
    }.map { it.fromAddress }.toList(),
)

data class PotentialVtable(val addr: Address, val slots: List<Address>, val refs: List<Address>) {
    constructor(pointers: List<Pointer>) : this(
        pointers.first().src,
        pointers.map { (_, dst) -> dst },
        pointers.first().refs,
    )
    val range get() = AddressRangeImpl(addr, (slots.size * addr.pointerSize).toLong())
}

class GenericVftableFinder(val program: Program) {
    val ptr = program.defaultPointerSize.toLong()
    val listing: Listing = program.listing

    val potentialVtables = program.findPointers().filter { (src, dst) ->
        program.isCode(dst) || program.importedFunction(src, dst) != null
    }.asIterable()
        .map { (src, dst) -> program.pointerOf(src, dst) }
        .chunkWith { a, b -> b.src == a.src + ptr && b.refs.isEmpty() }
        .map { PotentialVtable(it) }.filter { vt ->
            listing.getDefinedData(AddressSet(vt.range), true).all {
                it.baseDataType.length == program.defaultPointerSize
            }
        }

    fun run(monitor: TaskMonitor) {
        for (vtable in potentialVtables) {
            val structorNs = vtable.refs.mapNotNull {
                program.functionManager.getFunctionContaining(it)?.parentNamespace
            }
            if (structorNs.isEmpty()) {
                val ns = program.symbolTable.createClass(
                    program.globalNamespace,
                    "Klass_${vtable.addr}",
                    SourceType.ANALYSIS,
                )
                val sym = program.symbolTable.createLabel(vtable.addr, ClassNaming.VFTABLE, ns, SourceType.ANALYSIS)
            }
        }
    }
}
