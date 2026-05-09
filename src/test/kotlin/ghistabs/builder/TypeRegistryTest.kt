package ghistabs.builder

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.*
import ghistabs.importer.BookmarkSink
import ghistabs.parser.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class TypeRegistryTest : GhidraTestBase() {
    private fun newReg(): Pair<MockDtmTracker, TypeRegistry> {
        val tracker = MockDtmTracker()
        val dtm: DataTypeManager = mock()

        // Configure mock to track added types
        whenever(dtm.addDataType(any(), any())).thenAnswer { invocation ->
            val dataType = invocation.getArgument<DataType>(0)
            val handler = invocation.getArgument<DataTypeConflictHandler>(1)
            tracker.addDataType(dataType, handler)
        }

        whenever(dtm.getDataType(any<CategoryPath>(), any())).thenAnswer { invocation ->
            val cat = invocation.getArgument<CategoryPath>(0)
            val name = invocation.getArgument<String>(1)
            tracker.getDataType(cat, name)
        }

        whenever(dtm.startTransaction(any())).thenReturn(0)
        whenever(dtm.endTransaction(any(), any())).thenReturn(true)

        val program = mock<ghidra.program.model.listing.Program>()
        val bm = mock<ghidra.program.model.listing.BookmarkManager>()
        whenever(program.bookmarkManager).thenReturn(bm)
        whenever(bm.setBookmark(any(), any(), any(), any())).then { }
        val sink = BookmarkSink(program, MessageLog())
        return Pair(tracker, TypeRegistry(dtm, sink))
    }

    /**
     * Tracks data types added during tests
     */
    private class MockDtmTracker {
        private val types = mutableMapOf<Pair<CategoryPath, String>, DataType>()
        val allDataTypes: List<DataType> get() = types.values.toList()

        fun addDataType(
            dataType: DataType,
            handler: DataTypeConflictHandler,
        ): DataType {
            val key = dataType.categoryPath to dataType.name
            return if (handler == DataTypeConflictHandler.KEEP_HANDLER) {
                types.getOrPut(key) { dataType }
            } else {
                types[key] = dataType
                dataType
            }
        }

        fun getDataType(
            path: CategoryPath,
            name: String,
        ): DataType? = types[path to name]
    }

    private fun int32() = TypeDecl.Range(TypeId(0, 1), -2147483648L, 2147483647L)

    @Test fun testCrossUDedup() { // AC3.1
        val (dtm, reg) = newReg()
        val body =
            TypeDecl.Struct(
                AggrKind.STRUCT,
                8,
                emptyList(),
                listOf(FieldDecl("x", int32(), 0, 32, false), FieldDecl("y", int32(), 32, 32, false)),
                emptyList(),
                false,
                null,
            )
        val asts = listOf(TypeAst(TypeId(0, 5), "Foo", body, "/a.cpp"), TypeAst(TypeId(1, 5), "Foo", body, "/b.cpp"))
        reg.materialiseAll(asts) { n, cus -> Attribution.categoryFor(n, cus) }
        val foos =
            dtm.allDataTypes
                .asSequence()
                .filter { it.name == "Foo" }
                .toList()
        assertEquals(1, foos.size, "same body in 2 CUs → exactly one Foo")
    }

    @Test fun testConflictNaming() { // AC3.2
        val (dtm, reg) = newReg()
        val body1 =
            TypeDecl.Struct(
                AggrKind.STRUCT,
                8,
                emptyList(),
                listOf(FieldDecl("x", int32(), 0, 32, false), FieldDecl("y", int32(), 32, 32, false)),
                emptyList(),
                false,
                null,
            )
        val body2 =
            TypeDecl.Struct(
                AggrKind.STRUCT,
                8,
                emptyList(),
                listOf(FieldDecl("x", int32(), 0, 32, false), FieldDecl("z", TypeDecl.Range(TypeId(0, 2), 0L, 255L), 32, 32, false)),
                emptyList(),
                false,
                null,
            )
        val asts = listOf(TypeAst(TypeId(0, 5), "Foo", body1, "/a.cpp"), TypeAst(TypeId(1, 5), "Foo", body2, "/b.cpp"))
        reg.materialiseAll(asts) { n, cus -> Attribution.categoryFor(n, cus) }
        assertTrue(dtm.allDataTypes.asSequence().any { it.name == "Foo" }, "Foo must exist")
        assertTrue(dtm.allDataTypes.asSequence().any { it.name == "Foo_2" }, "Foo_2 must exist for conflict")
    }

    @Test fun testAttribution() { // AC3.3
        val (dtm, reg) = newReg()
        val body = TypeDecl.Struct(AggrKind.STRUCT, 4, emptyList(), emptyList(), emptyList(), false, null)
        reg.materialiseAll(listOf(TypeAst(TypeId(0, 5), "Foo", body, "/proj/foo.h"))) { n, cus -> Attribution.categoryFor(n, cus) }
        assertNotNull(dtm.getDataType(CategoryPath("/foo"), "Foo"), "Foo from foo.h must land at /foo")
    }

    @Test fun testSelfPointerCycle() { // AC3.4
        val (dtm, reg) = newReg()
        val nodeId = TypeId(0, 1)
        val body =
            TypeDecl.Struct(
                AggrKind.STRUCT,
                8,
                emptyList(),
                listOf(
                    FieldDecl("next", TypeDecl.Pointer(TypeDecl.Ref(nodeId)), 0, 32, false),
                    FieldDecl("val", int32(), 32, 32, false),
                ),
                emptyList(),
                false,
                null,
            )
        assertDoesNotThrow {
            reg.materialiseAll(
                listOf(TypeAst(nodeId, "Node", body, "/a.cpp")),
            ) { n, cus -> Attribution.categoryFor(n, cus) }
        }
        val node = dtm.allDataTypes.asSequence().find { it.name == "Node" }
        assertNotNull(node)
        assertEquals(8, node!!.length, "Node struct must have length == sizeBytes (8)")
    }

    @Test fun testMutualCycle() { // AC3.4
        val (dtm, reg) = newReg()
        val aId = TypeId(0, 1)
        val bId = TypeId(0, 2)
        val aBody =
            TypeDecl.Struct(
                AggrKind.STRUCT,
                4,
                emptyList(),
                listOf(FieldDecl("b", TypeDecl.Pointer(TypeDecl.Ref(bId)), 0, 32, false)),
                emptyList(),
                false,
                null,
            )
        val bBody =
            TypeDecl.Struct(
                AggrKind.STRUCT,
                4,
                emptyList(),
                listOf(FieldDecl("a", TypeDecl.Pointer(TypeDecl.Ref(aId)), 0, 32, false)),
                emptyList(),
                false,
                null,
            )
        assertDoesNotThrow {
            reg.materialiseAll(
                listOf(TypeAst(aId, "A", aBody, "/a.cpp"), TypeAst(bId, "B", bBody, "/a.cpp")),
            ) { n, cus -> Attribution.categoryFor(n, cus) }
        }
        assertNotNull(dtm.allDataTypes.asSequence().find { it.name == "A" })
        assertNotNull(dtm.allDataTypes.asSequence().find { it.name == "B" })
    }
}
