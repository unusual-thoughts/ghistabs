package ghidrakt
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMethodRecordMs
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOneMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOverloadedMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.ClassFieldMsAttributes

// The getters Ghidra 11.1 added to a PDB field list's methods. Before it the fields are protected, so
// they are read by reflection, under the names they had then.

val AbstractOneMethodMsType.attributes: ClassFieldMsAttributes get() = field("attribute")
val AbstractOneMethodMsType.offsetInVFTableIfIntroVirtual: Long get() = field("offsetInVFTableIfIntroVirtual")
val AbstractOneMethodMsType.procedureTypeRecordNumber: RecordNumber get() = field("procedureTypeRecordNumber")

val AbstractOverloadedMethodMsType.typeMethodListRecordNumber: RecordNumber get() = field("methodListRecordNumber")

val AbstractMethodRecordMs.attributes: ClassFieldMsAttributes get() = field("attributes")
val AbstractMethodRecordMs.optionalOffset: Long get() = field("optionalOffset")
val AbstractMethodRecordMs.procedureTypeRecordNumber: RecordNumber get() = field("procedureRecordNumber")

private inline fun <reified T> Any.field(name: String): T {
    val declared = generateSequence<Class<*>>(javaClass) { it.superclass }
        .firstNotNullOf { c -> c.declaredFields.firstOrNull { it.name == name } }
    return declared.apply { isAccessible = true }.get(this) as T
}
