package ghidrakt
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMethodRecordMs
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOneMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOverloadedMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.ClassFieldMsAttributes

// A PDB field list's methods. Before 11.1 their fields are protected with no getters, so they are read
// by reflection, under the names they had then.

val AbstractOneMethodMsType.methodAttributes: ClassFieldMsAttributes get() = field("attribute")
val AbstractOneMethodMsType.vftableOffset: Long get() = field("offsetInVFTableIfIntroVirtual")
val AbstractOneMethodMsType.procedureType: RecordNumber get() = field("procedureTypeRecordNumber")

val AbstractOverloadedMethodMsType.methodListType: RecordNumber get() = field("methodListRecordNumber")

val AbstractMethodRecordMs.methodAttributes: ClassFieldMsAttributes get() = field("attributes")
val AbstractMethodRecordMs.vftableOffset: Long get() = field("optionalOffset")
val AbstractMethodRecordMs.procedureType: RecordNumber get() = field("procedureRecordNumber")

private inline fun <reified T> Any.field(name: String): T {
    val declared = generateSequence<Class<*>>(javaClass) { it.superclass }
        .firstNotNullOf { c -> c.declaredFields.firstOrNull { it.name == name } }
    return declared.apply { isAccessible = true }.get(this) as T
}
