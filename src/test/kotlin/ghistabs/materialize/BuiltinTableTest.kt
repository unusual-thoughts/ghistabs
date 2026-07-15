package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.TypeDecl
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertInstanceOf

class BuiltinTableTest {
    private val cu = SourceFile.CUSource("test")

    @Test
    fun testClassifySignedInt32() {
        val kind = BuiltinTable.resolve(TypeDecl.Range(GlobalTypeId(cu, 1), -2147483648L, 2147483647L))
        assertInstanceOf<IntegerDataType>(kind)
        assertEquals(4, kind.length)
    }

    @Test
    fun testClassifyUnsignedInt32() {
        val kind = BuiltinTable.resolve(TypeDecl.Range(GlobalTypeId(cu, 1), 0L, 4294967295L))
        assertInstanceOf<UnsignedIntegerDataType>(kind)
        assertEquals(4, kind.length)
    }

    @Test
    fun testClassifyUnsignedByte() {
        val kind = BuiltinTable.resolve(TypeDecl.Range(GlobalTypeId(cu, 1), 0L, 255L))
        assertInstanceOf<ByteDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyPlainChar() {
        // gcc emits plain `char` as range 0..127 (not -128..127); it must map to char, not byte.
        val kind = BuiltinTable.resolve(TypeDecl.Range(GlobalTypeId(cu, 1), 0L, 127L))
        assertInstanceOf<CharDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyWithSizeAttr64ULL() {
        val kind = BuiltinTable.resolve(TypeDecl.WithSizeAttr(64, TypeDecl.Range(GlobalTypeId(cu, 6), 0L, -1L)))
        assertInstanceOf<UnsignedLongLongDataType>(kind)
        assertEquals(8, kind.length)
    }

    @Test
    fun testClassifyBool() {
        // gdb stabs encodes _Bool as (0,-16); after globalize the inner Ref to
        // a negative slot is hoisted into [TypeDecl.Builtin] so cross-CU
        // bool slots share one canonical hash and one Ghidra DataType.
        val kind = BuiltinTable.resolve(TypeDecl.WithSizeAttr(8, TypeDecl.Builtin(-16)))
        assertInstanceOf<BooleanDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyBuiltinSlotDirect() {
        // Builtin slot resolved standalone (no WithSizeAttr wrapper) — gcc
        // sometimes emits a bare `(0,-N)` Ref as a typedef body.
        assertInstanceOf<IntegerDataType>(BuiltinTable.resolve(TypeDecl.Builtin(-1)))
        assertInstanceOf<BooleanDataType>(BuiltinTable.resolve(TypeDecl.Builtin(-16)))
        assertInstanceOf<VoidDataType>(BuiltinTable.resolve(TypeDecl.Builtin(-11)))
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
        val kind = BuiltinTable.resolve(TypeDecl.Pointer(TypeDecl.Ref(GlobalTypeId(cu, 1))))
        assertEquals(null, kind)
    }
}
