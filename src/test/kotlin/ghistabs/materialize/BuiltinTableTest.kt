package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.TypeDecl
import ghistabs.test.longRange
import ghistabs.test.mustBe
import ghistabs.test.mustBeA
import org.junit.jupiter.api.Test
import java.math.BigInteger

class BuiltinTableTest {
    private val cu = SourceFile.CUSource("test")

    @Test
    fun testClassifySignedInt32() {
        val kind = longRange(GlobalTypeId(cu, 1), -2147483648L, 2147483647L).resolveBuiltin()
        kind.mustBeA<IntegerDataType>()
        kind?.length mustBe 4
    }

    @Test
    fun testClassifyUnsignedInt32() {
        val kind = longRange(GlobalTypeId(cu, 1), 0L, 4294967295L).resolveBuiltin()
        kind.mustBeA<UnsignedIntegerDataType>()
        kind?.length mustBe 4
    }

    @Test
    fun testClassifyUnsignedByte() {
        val kind = longRange(GlobalTypeId(cu, 1), 0L, 255L).resolveBuiltin()
        kind.mustBeA<ByteDataType>()
        kind?.length mustBe 1
    }

    @Test
    fun testClassifyPlainChar() {
        // gcc emits plain `char` as range 0..127 (not -128..127); it must map to char, not byte.
        val kind = longRange(GlobalTypeId(cu, 1), 0L, 127L).resolveBuiltin()
        kind.mustBeA<CharDataType>()
        kind?.length mustBe 1
    }

    @Test
    fun testClassifyWithSizeAttr64ULL() {
        val kind = TypeDecl.WithSizeAttr(64, longRange(GlobalTypeId(cu, 6), 0L, -1L)).resolveBuiltin()
        kind.mustBeA<UnsignedLongLongDataType>()
        kind?.length mustBe 8
    }

    @Test
    fun testAnOverflowingLiteralOutranksTheBase() {
        // gcc 2.6.3 writes both of these against `int` in one CU: `unsigned int:t4=r1;0;-1;` and
        // `long long unsigned int:t7=r1;0;01777777777777777777777;`. Both bounds truncate to -1L, so
        // only the literal's width separates four bytes from eight — the base cannot.
        val unfit = longRange(GlobalTypeId(cu, 1), 0L, -1L)
        val spelledOut = TypeDecl.Range(GlobalTypeId(cu, 1), BigInteger.ZERO, BigInteger.TWO.pow(64) - BigInteger.ONE)
        // They narrow to the same (min, max) pair, which is exactly why the exact bound is kept.
        (unfit.min to unfit.max) mustBe (spelledOut.min to spelledOut.max)
        TypeDecl.WithSizeAttr(32, unfit).resolveBuiltin().mustBeA<UnsignedIntegerDataType>()
        spelledOut.resolveBuiltin().mustBeA<UnsignedLongLongDataType>()
        // ...and they must not hash as one type.
        (unfit.layoutData == spelledOut.layoutData) mustBe false
    }

    @Test
    fun testUnfitBoundsTakeTheBaseWidth() {
        // Sun's C compiler writes 32-bit `unsigned int:t(0,8)=r(0,1);0;-1;` — same bounds as gcc's
        // `long long unsigned int`, four bytes wide. Only the base type says which, so a caller that
        // resolved it (the `int` at (0,1)) restates it as `@s32`, which must outrank the 8 the bounds
        // alone imply — see `DataTypeRegistry.atBaseWidth`.
        val range = longRange(GlobalTypeId(cu, 1), 0L, -1L)
        TypeDecl.WithSizeAttr(32, range).resolveBuiltin().mustBeA<UnsignedIntegerDataType>()
        // No base resolved → gcc's reading, which is what the self-referential form means.
        range.resolveBuiltin().mustBeA<UnsignedLongLongDataType>()
    }

    @Test
    fun testSizeAttrOutranksRangeBounds() {
        // `@s128;r(0,25);0;0377…;` — the 128-bit max truncates to -1L, so the bounds alone claim
        // 8 bytes. The attribute must win, or __int128 materializes at half its width.
        val kind = TypeDecl.WithSizeAttr(128, longRange(GlobalTypeId(cu, 25), 0L, -1L)).resolveBuiltin()
        kind.mustBeA<UnsignedInteger16DataType>()
        kind?.length mustBe 16
    }

    @Test
    fun testSizeAttrKeepsCharIdentity() {
        // `@s8;r(0,10);-128;127;` — the attribute governs width, not identity: still char, not int8.
        val kind = TypeDecl.WithSizeAttr(8, longRange(GlobalTypeId(cu, 10), -128L, 127L)).resolveBuiltin()
        kind.mustBeA<CharDataType>()
        kind?.length mustBe 1
    }

    @Test
    fun testClassifyBool() {
        // gdb stabs encodes _Bool as (0,-16); after globalize the inner Ref to
        // a negative slot is hoisted into [TypeDecl.Builtin] so cross-CU
        // bool slots share one canonical hash and one Ghidra DataType.
        val kind = TypeDecl.WithSizeAttr<GlobalTypeId>(8, TypeDecl.Builtin(-16)).resolveBuiltin()
        kind.mustBeA<BooleanDataType>()
        kind?.length mustBe 1
    }

    @Test
    fun testClassifyBuiltinSlotDirect() {
        // Builtin slot resolved standalone (no WithSizeAttr wrapper) — gcc
        // sometimes emits a bare `(0,-N)` Ref as a typedef body.
        TypeDecl.Builtin<GlobalTypeId>(-1).resolveBuiltin().mustBeA<IntegerDataType>()
        TypeDecl.Builtin<GlobalTypeId>(-16).resolveBuiltin().mustBeA<BooleanDataType>()
        TypeDecl.Builtin<GlobalTypeId>(-11).resolveBuiltin().mustBeA<VoidDataType>()
    }

    @Test
    fun testClassifyComplex8() {
        val kind = TypeDecl.Complex<GlobalTypeId>(3, 8).resolveBuiltin()
        kind.mustBeA<Complex8DataType>()
        kind?.length mustBe 8
    }

    @Test
    fun testClassifyComplex16() {
        val kind = TypeDecl.Complex<GlobalTypeId>(4, 16).resolveBuiltin()
        kind.mustBeA<Complex16DataType>()
        kind?.length mustBe 16
    }

    @Test
    fun testClassifyNonPrimitive() {
        val kind = TypeDecl.Pointer(TypeDecl.Ref(GlobalTypeId(cu, 1))).resolveBuiltin()
        kind mustBe null
    }
}
