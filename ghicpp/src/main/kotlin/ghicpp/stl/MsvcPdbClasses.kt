package ghicpp.stl

import ghicpp.Access
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractBaseClassMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractComplexMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractCompositeMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractFieldListMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMethodListMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOneMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractOverloadedMethodMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractUnionMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractVirtualBaseClassMsType
import ghidra.app.util.bin.format.pdb2.pdbreader.type.ClassFieldMsAttributes
import ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypePath

/** [StdClasses] off an MSVC runtime's PDB, for `MsvcStlArchiveScript`. */
object MsvcPdbClasses {
    /**
     * What [read] reads: the [classes], and each slot's function type as [applicator] applied it, where it
     * did ([typeOf]).
     */
    class Read(val classes: StdClasses, private val types: Map<Pair<String, Long>, DataType>) {
        fun typeOf(cls: StdClass, slot: StdSlot): DataType? = types[cls.path to slot.offset]
    }

    /**
     * The direct bases of each class [pdb] defines that [paths] files, by the C++ name the PDB applicator
     * gives it (its spaces made underscores) to its path in the archive, in path order. A class the PDB
     * defines twice (once per compiland) is read once. A base outside [paths] goes by its C++ name,
     * `::` made `/`. Its slots are the virtual functions it introduces, typed off [applicator] once it has
     * applied the PDB's types.
     */
    @JvmStatic
    @JvmOverloads
    fun read(pdb: AbstractPdb, paths: Map<String, DataTypePath>, applicator: DefaultPdbApplicator? = null): Read {
        val classes = sortedMapOf<String, StdClass>()
        val types = mutableMapOf<Pair<String, Long>, DataType>()
        val tpi = pdb.typeProgramInterface
        for (i in tpi.typeIndexMin..<tpi.typeIndexMaxExclusive) {
            val type = pdb.getTypeRecord(RecordNumber.typeRecordNumber(i))
            if (type !is AbstractCompositeMsType || type is AbstractUnionMsType) continue
            if (type.msProperty.isForwardReference) continue
            val path = paths[spelled(type.name)]?.path ?: continue
            val fields = type.fieldDescriptorListType as? AbstractFieldListMsType ?: continue
            if (path in classes) continue
            val bases = fields.baseClassList.mapNotNull { field ->
                when (field) {
                    is AbstractBaseClassMsType -> StdBase(
                        basePath(pdb, field.baseClassRecordNumber, paths),
                        access(field.attributes),
                        offset = field.offset.toLong(),
                    )

                    is AbstractVirtualBaseClassMsType ->
                        StdBase(basePath(pdb, field.baseClassRecordNumber, paths), access(field.attributes), true)

                    else -> null
                }
            }
            val slots = introduced(pdb, fields).map { (slot, procedure) ->
                applicator?.let { appliedType(it, procedure) }?.let { types[path to slot.offset] = it }
                slot
            }
            classes[path] = StdClass(path, bases, slots)
        }
        return Read(StdClasses(classes.values.toList()), types)
    }

    /** The virtual functions [fields] introduce, each with its function type's record, in vftable order. */
    private fun introduced(pdb: AbstractPdb, fields: AbstractFieldListMsType): List<Pair<StdSlot, RecordNumber>> =
        fields.methodList.flatMap { field ->
            when (field) {
                is AbstractOneMethodMsType -> listOfNotNull(
                    field.takeIf { it.attributes.isIntro() }
                        ?.let { StdSlot(it.offsetInVFTableIfIntroVirtual, it.name) to it.procedureTypeRecordNumber },
                )

                is AbstractOverloadedMethodMsType ->
                    (pdb.getTypeRecord(field.typeMethodListRecordNumber) as? AbstractMethodListMsType)?.list.orEmpty()
                        .filter { it.attributes.isIntro() }
                        .map { StdSlot(it.optionalOffset, field.name) to it.procedureTypeRecordNumber }

                else -> emptyList()
            }
        }.distinctBy { it.first.offset }.sortedBy { it.first.offset }

    private fun ClassFieldMsAttributes.isIntro() =
        property == ClassFieldMsAttributes.Property.INTRO || property == ClassFieldMsAttributes.Property.INTRO_PURE

    /**
     * The type [applicator] gave the record: its lookup is package-private, so it is reached by reflection,
     * and null where a Ghidra release has none.
     */
    private fun appliedType(applicator: DefaultPdbApplicator, record: RecordNumber): DataType? = runCatching {
        GET_DATA_TYPE?.invoke(applicator, record) as? DataType
    }.getOrNull()

    private val GET_DATA_TYPE by lazy {
        runCatching {
            DefaultPdbApplicator::class.java.getDeclaredMethod("getDataType", RecordNumber::class.java)
                .apply { isAccessible = true }
        }.getOrNull()
    }

    /** The applicator names a type with its spaces made underscores; both sides are keyed that way. */
    @JvmStatic
    fun spelled(cxxName: String) = cxxName.replace(' ', '_')

    private fun basePath(pdb: AbstractPdb, record: RecordNumber, paths: Map<String, DataTypePath>): String {
        val type = pdb.getTypeRecord(record)
        val name = spelled((type as? AbstractComplexMsType)?.name ?: type.name)
        return paths[name]?.path ?: ("/" + name.replace("::", "/"))
    }

    private fun access(attributes: ClassFieldMsAttributes) = when (attributes.access) {
        ClassFieldMsAttributes.Access.PRIVATE -> Access.PRIVATE
        ClassFieldMsAttributes.Access.PROTECTED -> Access.PROTECTED
        else -> Access.PUBLIC
    }
}
