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
        val kind = TypeDecl.Range(GlobalTypeId(cu, 1), -2147483648L, 2147483647L).resolveBuiltin()
        assertInstanceOf<IntegerDataType>(kind)
        assertEquals(4, kind.length)
    }

    @Test
    fun testClassifyUnsignedInt32() {
        val kind = TypeDecl.Range(GlobalTypeId(cu, 1), 0L, 4294967295L).resolveBuiltin()
        assertInstanceOf<UnsignedIntegerDataType>(kind)
        assertEquals(4, kind.length)
    }

    @Test
    fun testClassifyUnsignedByte() {
        val kind = TypeDecl.Range(GlobalTypeId(cu, 1), 0L, 255L).resolveBuiltin()
        assertInstanceOf<ByteDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyPlainChar() {
        // gcc emits plain `char` as range 0..127 (not -128..127); it must map to char, not byte.
        val kind = TypeDecl.Range(GlobalTypeId(cu, 1), 0L, 127L).resolveBuiltin()
        assertInstanceOf<CharDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyWithSizeAttr64ULL() {
        val kind = TypeDecl.WithSizeAttr(64, TypeDecl.Range(GlobalTypeId(cu, 6), 0L, -1L)).resolveBuiltin()
        assertInstanceOf<UnsignedLongLongDataType>(kind)
        assertEquals(8, kind.length)
    }

    @Test
    fun testSizeAttrOutranksRangeBounds() {
        // `@s128;r(0,25);0;0377…;` — the 128-bit max truncates to -1L, so the bounds alone claim
        // 8 bytes. The attribute must win, or __int128 materializes at half its width.
        val kind = TypeDecl.WithSizeAttr(128, TypeDecl.Range(GlobalTypeId(cu, 25), 0L, -1L)).resolveBuiltin()
        assertInstanceOf<UnsignedInteger16DataType>(kind)
        assertEquals(16, kind.length)
    }

    @Test
    fun testSizeAttrKeepsCharIdentity() {
        // `@s8;r(0,10);-128;127;` — the attribute governs width, not identity: still char, not int8.
        val kind = TypeDecl.WithSizeAttr(8, TypeDecl.Range(GlobalTypeId(cu, 10), -128L, 127L)).resolveBuiltin()
        assertInstanceOf<CharDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyBool() {
        // gdb stabs encodes _Bool as (0,-16); after globalize the inner Ref to
        // a negative slot is hoisted into [TypeDecl.Builtin] so cross-CU
        // bool slots share one canonical hash and one Ghidra DataType.
        val kind = TypeDecl.WithSizeAttr<GlobalTypeId>(8, TypeDecl.Builtin(-16)).resolveBuiltin()
        assertInstanceOf<BooleanDataType>(kind)
        assertEquals(1, kind.length)
    }

    @Test
    fun testClassifyBuiltinSlotDirect() {
        // Builtin slot resolved standalone (no WithSizeAttr wrapper) — gcc
        // sometimes emits a bare `(0,-N)` Ref as a typedef body.
        assertInstanceOf<IntegerDataType>(TypeDecl.Builtin<GlobalTypeId>(-1).resolveBuiltin())
        assertInstanceOf<BooleanDataType>(TypeDecl.Builtin<GlobalTypeId>(-16).resolveBuiltin())
        assertInstanceOf<VoidDataType>(TypeDecl.Builtin<GlobalTypeId>(-11).resolveBuiltin())
    }

    @Test
    fun testClassifyComplex8() {
        val kind = TypeDecl.Complex<GlobalTypeId>(3, 8).resolveBuiltin()
        assertInstanceOf<Complex8DataType>(kind)
        assertEquals(8, kind.length)
    }

    @Test
    fun testClassifyComplex16() {
        val kind = TypeDecl.Complex<GlobalTypeId>(4, 16).resolveBuiltin()
        assertInstanceOf<Complex16DataType>(kind)
        assertEquals(16, kind.length)
    }

    @Test
    fun testClassifyNonPrimitive() {
        val kind = TypeDecl.Pointer(TypeDecl.Ref(GlobalTypeId(cu, 1))).resolveBuiltin()
        assertEquals(null, kind)
    }
}
