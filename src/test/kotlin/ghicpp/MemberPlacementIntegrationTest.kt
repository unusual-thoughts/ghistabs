package ghicpp

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DWordDataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.diagnose.CapturingSink
import ghistabs.runTransaction
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [placeMember] on hand-built class structs: `Owner`, 0x20 bytes, a `{vfptr}` at 0 and its own fields at 4 in an
 * `Owner_data` struct, laid whole ([VfptrModel.INHERITED]) or, split around a deriving class's vptr
 * ([VfptrModel.SPLIT_BASE]), inside an `Owner_fields` run; and an 8-byte `Member` to lay in it.
 */
@Tag("integration")
class MemberPlacementIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program
    private val sink = CapturingSink()
    private val category = CategoryPath("/ClassDataTypes/Owner")

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("member-placement", ProgramBuilder._X86)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun <T> edit(block: () -> T): T {
        var result: T? = null
        program.runTransaction("place") { result = block() }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }

    private fun add(struct: Structure) =
        program.dataTypeManager.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER) as Structure

    private fun member() = add(
        StructureDataType(CategoryPath("/ClassDataTypes/Member"), "Member", 8).apply {
            replaceAtOffset(0, DWordDataType.dataType, 4, "a", null)
        },
    )

    /** `Owner_data`, from +[start] to +0x20, with a dword at each of [fields], by offset into the class. */
    private fun data(start: Int, vararg fields: Int) = add(
        StructureDataType(category, "Owner_data", 0x20 - start).apply {
            for (at in fields) {
                replaceAtOffset(
                    at - start,
                    DWordDataType.dataType,
                    4,
                    "field_0x${at.toString(16)}",
                    null,
                )
            }
        },
    )

    /** `Owner`, its `{vfptr}` at 0, then [own] at +[start]. */
    private fun owner(own: Structure, start: Int) = add(
        StructureDataType(category, "Owner", 0x20).apply {
            replaceAtOffset(0, PointerDataType.dataType, 4, "{vfptr}", null)
            replaceAtOffset(start, own, own.length, own.name, "own fields")
        },
    )

    private fun unplaced() = sink.lines.filter { it.tag == "member-unplaced" }

    @Test
    fun `a member goes over the plain fields of its holder's own fields`() {
        val (owner, member) = edit { owner(data(4, 4, 0xc), 4) to member() }
        edit { sink.placeMember(owner, 8, member) }
        val own = owner.getComponentAt(4).dataType as Structure
        own.getComponentAt(4).dataType mustBe member
        own.getComponentContaining(8).offset mustBe 4
        own.getComponentAt(0).fieldName mustBe "field_0x4"
        unplaced() mustBe emptyList()
    }

    @Test
    fun `a member running into its holder's own fields stretches them back to hold it`() {
        val (owner, member) = edit { owner(data(0xc, 0xc), 0xc) to member() }
        edit { sink.placeMember(owner, 8, member) }
        val own = owner.getComponentAt(8).dataType as Structure
        own.name mustBe "Owner_data"
        own.length mustBe 0x18
        own.getComponentAt(0).dataType mustBe member
        owner.length mustBe 0x20
        unplaced() mustBe emptyList()
    }

    @Test
    fun `split around a vptr, a member goes in the own fields inside the class's fields run`() {
        val (owner, member) = edit {
            val run = add(
                StructureDataType(category, "Owner_fields_4_32", 0x1c).apply {
                    val own = data(4, 4, 0xc)
                    replaceAtOffset(0, own, own.length, own.name, "own fields")
                },
            )
            owner(run, 4) to member()
        }
        edit { sink.placeMember(owner, 8, member) }
        val run = owner.getComponentAt(4).dataType as Structure
        val own = run.getComponentAt(0).dataType as Structure
        own.name mustBe "Owner_data"
        own.getComponentAt(4).dataType mustBe member
        unplaced() mustBe emptyList()
    }

    @Test
    fun `a member over the vptr is left unplaced with a warning`() {
        val (owner, member) = edit { owner(data(4, 4), 4) to member() }
        edit { sink.placeMember(owner, 2, member) }
        unplaced().single().msg!!.contains("{vfptr} at +0x0") mustBe true
        (owner.getComponentAt(4).dataType as Structure).getComponentAt(0).fieldName mustBe "field_0x4"
    }

    @Test
    fun `in a base's struct a member goes over undefined bytes only`() {
        val (holder, member) = edit {
            val base = add(
                StructureDataType(CategoryPath("/ClassDataTypes/Base"), "Base", 0x10).apply {
                    replaceAtOffset(0xc, DWordDataType.dataType, 4, "field_0xc", null)
                },
            )
            add(
                StructureDataType(category, "Owner", 0x20).apply {
                    replaceAtOffset(0, base, base.length, "_base_", "public Base")
                },
            ) to member()
        }
        val base = holder.getComponentAt(0).dataType as Structure
        edit { sink.placeMember(holder, 0, member) }
        base.getComponentAt(0).dataType mustBe member
        edit { sink.placeMember(holder, 8, member) }
        base.definedComponents.map { it.offset } mustBe listOf(0, 0xc)
        unplaced().single().msg!!.contains("field_0xc at +0xc in Base") mustBe true
    }
}
