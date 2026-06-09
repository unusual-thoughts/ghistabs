package ghistabs.parser

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
        val expected = SymbolDecl.Typedef(
            name = "_Bool",
            id = LocalTypeId(0, 21),
            type = TypeDecl.WithSizeAttr(
                sizeBits = 8,
                inner = TypeDecl.Ref(LocalTypeId(0, -16)),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testIntRange() {
        val input = "int:t(0,1)=r(0,1);-2147483648;2147483647;"
        val expected = SymbolDecl.Typedef(
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
        val expected = SymbolDecl.Typedef(
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
    fun testComplexFloat() {
        val input = "complex float:t(0,16)=R3;8;0;"
        val expected = SymbolDecl.Typedef(
            name = "complex float",
            id = LocalTypeId(0, 16),
            type = TypeDecl.Complex(rCode = 3, sizeBytes = 8),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testComplexDouble() {
        val input = "complex double:t(0,17)=R4;16;0;"
        val expected = SymbolDecl.Typedef(
            name = "complex double",
            id = LocalTypeId(0, 17),
            type = TypeDecl.Complex(rCode = 4, sizeBytes = 16),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testPointerToInt() {
        val input = "pi:t(0,30)=*(0,1)"
        val expected = SymbolDecl.Typedef(
            name = "pi",
            id = LocalTypeId(0, 30),
            type = TypeDecl.Pointer(TypeDecl.Ref(LocalTypeId(0, 1))),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testConstPointerToInt() {
        val input = "cpi:t(0,31)=k*(0,1)"
        val expected = SymbolDecl.Typedef(
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
        val expected = SymbolDecl.Typedef(
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
        val expected = SymbolDecl.Typedef(
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
        val expected = SymbolDecl.Typedef(
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
        val expected = SymbolDecl.Typedef(
            name = "fn_type",
            id = LocalTypeId(0, 35),
            type = TypeDecl.FunctionT(ret = TypeDecl.Ref(LocalTypeId(0, 1)), params = emptyList()),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }
}
