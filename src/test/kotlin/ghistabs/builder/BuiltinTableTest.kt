package ghistabs.builder

import ghidra.program.model.data.*
import ghistabs.parser.LocalTypeId
import ghistabs.parser.TypeDecl
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertInstanceOf

/**
 * Pure unit tests for BuiltinTable core logic.
 * Tests the data type classification algorithm without mocking DataTypeManager.
 */
class BuiltinTableTest {
    @Test
    fun testClassifySignedInt32() {
        val kind = BuiltinTable.resolve(TypeDecl.Range(LocalTypeId(0, 1), -2147483648L, 2147483647L))
        assertInstanceOf<IntegerDataType>(kind)
        assertEquals(4, kind.length)
    }

    @Test
    fun testClassifyUnsignedInt32() {
        val kind = BuiltinTable.resolve(TypeDecl.Range(LocalTypeId(0, 1), 0L, 4294967295L))
        assertInstanceOf<UnsignedIntegerDataType>(kind)
        assertEquals(4, kind.length)
    }

    @Test
    fun testClassifyUnsignedByte() {
        val kind = BuiltinTable.resolve(TypeDecl.Range(LocalTypeId(0, 1), 0L, 255L))
        assertInstanceOf<ByteDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyWithSizeAttr64ULL() {
        val kind = BuiltinTable.resolve(TypeDecl.WithSizeAttr(64, TypeDecl.Range(LocalTypeId(0, 6), 0L, -1L)))
        assertInstanceOf<UnsignedLongLongDataType>(kind)
        assertEquals(8, kind.length)
    }

    @Test
    fun testClassifyBool() {
        val kind = BuiltinTable.resolve(TypeDecl.WithSizeAttr(8, TypeDecl.Ref(LocalTypeId(0, -16))))
        assertInstanceOf<BooleanDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyComplex8() {
        val kind = BuiltinTable.resolve(TypeDecl.Complex(3, 8))
        assertInstanceOf<Complex8DataType>(kind)
        assertEquals(8, kind.length)
    }

    @Test
    fun testClassifyComplex16() {
        val kind = BuiltinTable.resolve(TypeDecl.Complex(4, 16))
        assertInstanceOf<Complex16DataType>(kind)
        assertEquals(16, kind.length)
    }

    @Test
    fun testClassifyNonPrimitive() {
        val kind = BuiltinTable.resolve(TypeDecl.Pointer(TypeDecl.Ref(LocalTypeId(0, 1))))
        assertEquals(kind, null)
    }
}
