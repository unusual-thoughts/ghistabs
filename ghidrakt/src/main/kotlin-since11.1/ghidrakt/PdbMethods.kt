package ghidrakt
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMethodRecordMs
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOneMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOverloadedMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.ClassFieldMsAttributes

// A PDB field list's methods, read through the getters Ghidra 11.1 added.

val AbstractOneMethodMsType.methodAttributes: ClassFieldMsAttributes get() = attributes
val AbstractOneMethodMsType.vftableOffset: Long get() = offsetInVFTableIfIntroVirtual
val AbstractOneMethodMsType.procedureType: RecordNumber get() = procedureTypeRecordNumber

val AbstractOverloadedMethodMsType.methodListType: RecordNumber get() = typeMethodListRecordNumber

val AbstractMethodRecordMs.methodAttributes: ClassFieldMsAttributes get() = attributes
val AbstractMethodRecordMs.vftableOffset: Long get() = optionalOffset
val AbstractMethodRecordMs.procedureType: RecordNumber get() = procedureTypeRecordNumber
