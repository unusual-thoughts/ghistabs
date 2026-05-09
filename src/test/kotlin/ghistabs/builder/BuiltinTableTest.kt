package ghistabs.builder

import ghidra.program.model.data.*
import ghistabs.parser.TypeDecl
import ghistabs.parser.TypeId
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

class BuiltinTableTest {
    // Mock DTM for testing - BuiltinTable.resolve should work with any DTM
    private val dtm: DataTypeManager = mock()

    @Test
    fun testSignedInt32() {
        val r = BuiltinTable.resolve(TypeDecl.Range(TypeId(0, 1), -2147483648L, 2147483647L), dtm)!!
        assertEquals(4, r.length)
        assertTrue(r is AbstractSignedIntegerDataType, "expected signed int, got ${r::class}")
    }

    @Test
    fun testUnsignedInt32() {
        val r = BuiltinTable.resolve(TypeDecl.Range(TypeId(0, 1), 0L, 4294967295L), dtm)!!
        assertEquals(4, r.length)
        assertTrue(r is AbstractUnsignedIntegerDataType || r.name.contains("uint", ignoreCase = true))
    }

    @Test
    fun testUnsignedByte() {
        val r = BuiltinTable.resolve(TypeDecl.Range(TypeId(0, 1), 0L, 255L), dtm)!!
        assertEquals(1, r.length)
    }

    @Test
    fun testWithSizeAttr64ULL() {
        val r = BuiltinTable.resolve(TypeDecl.WithSizeAttr(64, TypeDecl.Range(TypeId(0, 6), 0L, -1L)), dtm)!!
        assertEquals(8, r.length)
    }

    @Test
    fun testBool() {
        val r = BuiltinTable.resolve(TypeDecl.WithSizeAttr(8, TypeDecl.Ref(TypeId(0, -16))), dtm)!!
        assertTrue(r is BooleanDataType)
    }

    @Test
    fun testComplex8() {
        val r = BuiltinTable.resolve(TypeDecl.Complex(3, 8), dtm)!!
        assertTrue(r is Complex8DataType)
    }

    @Test
    fun testComplex16() {
        val r = BuiltinTable.resolve(TypeDecl.Complex(4, 16), dtm)!!
        assertTrue(r is Complex16DataType)
    }

    @Test
    fun testNonPrimitive() {
        val r = BuiltinTable.resolve(TypeDecl.Pointer(TypeDecl.Ref(TypeId(0, 1))), dtm)
        assertNull(r)
    }
}
