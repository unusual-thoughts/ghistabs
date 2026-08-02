package ghistabs.parse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * ParserPrimitiveTest: Tests for primitive type forms.
 *
 * Verifies AC2.2 (size attributes), AC2.3 (complex types), and pointer/const forms.
 */
class ParserPrimitiveTest {
    @Test
    fun testBoolWithSizeAttr() {
        val input = "_Bool:t(0,21)=@s8;-16"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "_Bool",
            id = LocalTypeId(0, 21),
            type = TypeDecl.WithSizeAttr(
                sizeBits = 8,
                // Parser hoists `(0,-N)` Refs to [TypeDecl.Builtin] directly
                // — the stabs spec says no stab defines these slots, so
                // they're builtin from the moment they're read.
                inner = TypeDecl.Builtin(-16),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testIntRange() {
        val input = "int:t(0,1)=r(0,1);-2147483648;2147483647;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "int",
            id = LocalTypeId(0, 1),
            type = TypeDecl.Range(
                of = LocalTypeId(0, 1),
                min = -2147483648L,
                max = 2147483647L,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testLongLongIntWithSizeAttrOctal() {
        val input = "long long int:t(0,6)=@s64;r(0,6);0000000000000;01777777777777777777777;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "long long int",
            id = LocalTypeId(0, 6),
            type = TypeDecl.WithSizeAttr(
                sizeBits = 64,
                inner = TypeDecl.Range(
                    of = LocalTypeId(0, 6),
                    min = 0L,
                    max = -1L, // octal 01777777777777777777777 = 2^64-1 = -1L when signed
                ),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testInt128WithSizeAttrOctal() {
        // gcc 3.4.5 emits 128-bit types with a 96+-bit octal upper bound that overflows a
        // 64-bit parse; it must fold to the low 64 bits (all ones = -1L) rather than throw.
        val input = "__int128:t(0,25)=@s128;r(0,25);000000000000000000000000;037777777777777777777777777777777;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "__int128",
            id = LocalTypeId(0, 25),
            type = TypeDecl.WithSizeAttr(
                sizeBits = 128,
                inner = TypeDecl.Range(
                    of = LocalTypeId(0, 25),
                    min = 0L,
                    max = -1L, // octal 037777777777777777777777777777777 truncated to low 64 bits
                ),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testIntegerConstantDescriptor() {
        // gcc emits static-const integral members as `name:c=iVALUE` (no type info). The value
        // may exceed signed int (INFINITE_TIME = 0xFFFFFFFF) but fits in Long.
        val input = "_ZN8CryptoPP13INFINITE_TIMEE:c=i4294967295"
        val expected = SymbolDecl.Constant(
            name = "_ZN8CryptoPP13INFINITE_TIMEE",
            type = TypeDecl.Builtin(-1),
            value = 4294967295L,
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testTypedEnumConstantDescriptor() {
        // `c=e<type>,<value>` carries an explicit type before the value.
        val input = "kBlue:c=e(0,3),2"
        val expected = SymbolDecl.Constant(
            name = "kBlue",
            type = TypeDecl.Ref(LocalTypeId(0, 3)),
            value = 2L,
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testComplexFloat() {
        val input = "complex float:t(0,16)=R3;8;0;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "complex float",
            id = LocalTypeId(0, 16),
            type = TypeDecl.Complex(rCode = 3, sizeBytes = 8),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testComplexDouble() {
        val input = "complex double:t(0,17)=R4;16;0;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "complex double",
            id = LocalTypeId(0, 17),
            type = TypeDecl.Complex(rCode = 4, sizeBytes = 16),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testPointerToInt() {
        val input = "pi:t(0,30)=*(0,1)"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "pi",
            id = LocalTypeId(0, 30),
            type = TypeDecl.Pointer(TypeDecl.Ref(LocalTypeId(0, 1))),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testConstPointerToInt() {
        val input = "cpi:t(0,31)=k*(0,1)"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "cpi",
            id = LocalTypeId(0, 31),
            type = TypeDecl.Const(TypeDecl.Pointer(TypeDecl.Ref(LocalTypeId(0, 1)))),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testArrayOfInts() {
        // Array descriptor: ar<index-type>;<lower>;<upper>;<element-type>
        // stabs PDF §5.3: array of 10 ints (0..9)
        // Note: Parser stores the index type (range) and element type; length is null.
        val input = "int_array:t(0,32)=ar(0,1);0;9;(0,1)"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "int_array",
            id = LocalTypeId(0, 32),
            type = TypeDecl.Array(
                element = TypeDecl.Ref(LocalTypeId(0, 1)),
                length = null,
                indexType = TypeDecl.Range(
                    of = LocalTypeId(0, 1),
                    min = 0L,
                    max = 9L,
                ),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testReferenceToInt() {
        // C++ reference descriptor: &<referent-type>
        // stabs PDF §5.6
        val input = "ref_int:t(0,33)=&(0,1)"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "ref_int",
            id = LocalTypeId(0, 33),
            type = TypeDecl.Reference(TypeDecl.Ref(LocalTypeId(0, 1))),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testVolatileInt() {
        // Volatile qualifier: B<inner-type>
        // stabs PDF §5.7
        val input = "vol_int:t(0,34)=B(0,1)"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "vol_int",
            id = LocalTypeId(0, 34),
            type = TypeDecl.Volatile(TypeDecl.Ref(LocalTypeId(0, 1))),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testFunctionType() {
        // Function type descriptor: f<return-type>
        // stabs PDF §5.5
        val input = "fn_type:t(0,35)=f(0,1)"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TYPEDEF,
            name = "fn_type",
            id = LocalTypeId(0, 35),
            type = TypeDecl.FunctionT(ret = TypeDecl.Ref(LocalTypeId(0, 1)), params = emptyList()),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }
}
