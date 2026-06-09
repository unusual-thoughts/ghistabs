package ghistabs.parser

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * ParserClassTest: Tests for C++ class grammar.
 *
 * Verifies AC2.4: inheritance, methods, vtable markers, and static fields.
 */
class ParserClassTest {
    @Test
    fun testPlainStruct() {
        val input = "Foo:T(0,5)=s8x:(0,1),0,32;y:(0,1),32,32;;;"
        val expected = SymbolDecl.TaggedType(
            name = "Foo",
            id = LocalTypeId(0, 5),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 8,
                bases = emptyList(),
                fields = listOf(
                    FieldDecl("x", TypeDecl.Ref(LocalTypeId(0, 1)), offsetBits = 0, sizeBits = 32, isStatic = false),
                    FieldDecl(
                        "y",
                        TypeDecl.Ref(LocalTypeId(0, 1)),
                        offsetBits = 32,
                        sizeBits = 32,
                        isStatic = false,
                    ),
                ),
                methods = emptyList(),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testSingleInheritanceNonVirtual() {
        val input = "Bar:T(0,6)=s4!1,020,(0,5);;;"
        val expected = SymbolDecl.TaggedType(
            name = "Bar",
            id = LocalTypeId(0, 6),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases =
                listOf(
                    BaseDecl(
                        type = TypeDecl.Ref(LocalTypeId(0, 5)),
                        isVirtual = false,
                        access = Access.PUBLIC,
                        offsetBits = 0,
                    ),
                ),
                fields = emptyList(),
                methods = emptyList(),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testClassWithVTablePointerMarker() {
        val input = "Baz:T(0,7)=s8~%(0,8);;;"
        val expected = SymbolDecl.TaggedType(
            name = "Baz",
            id = LocalTypeId(0, 7),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 8,
                bases = emptyList(),
                fields = emptyList(),
                methods = emptyList(),
                hasVTablePointerMarker = true,
                vtableTargetTypeId = LocalTypeId(0, 8),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testMethodWithMangledSymbol() {
        val input = "Qux:T(0,9)=s4doIt::(0,10)=#(0,9),(0,1),(0,2);:_ZN3Qux4doItEi;2A.;;"
        val expected = SymbolDecl.TaggedType(
            name = "Qux",
            id = LocalTypeId(0, 9),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    MethodDecl(
                        name = "doIt",
                        mangled = "_ZN3Qux4doItEi",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 10),
                            body = TypeDecl.Method(
                                cls = TypeDecl.Ref(LocalTypeId(0, 9)),
                                ret = TypeDecl.Ref(LocalTypeId(0, 1)),
                                params = listOf(TypeDecl.Ref(LocalTypeId(0, 2))),
                            ),
                        ),
                        access = Access.PUBLIC,
                        virt = VirtKind.NORMAL,
                        isConst = false,
                        isVolatile = false,
                        vtableOffsetBits = null,
                    ),
                ),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testVirtualMethod() {
        val input = "Qux:T(0,9)=s4doIt::(0,10)=#(0,9),(0,1),(0,2);:_ZN3Qux4doItEi;2A*0;(0,9);;;"
        val expected = SymbolDecl.TaggedType(
            name = "Qux",
            id = LocalTypeId(0, 9),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    MethodDecl(
                        name = "doIt",
                        mangled = "_ZN3Qux4doItEi",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 10),
                            body = TypeDecl.Method(
                                cls = TypeDecl.Ref(LocalTypeId(0, 9)),
                                ret = TypeDecl.Ref(LocalTypeId(0, 1)),
                                params = listOf(TypeDecl.Ref(LocalTypeId(0, 2))),
                            ),
                        ),
                        access = Access.PUBLIC,
                        virt = VirtKind.VIRTUAL,
                        isConst = false,
                        isVolatile = false,
                        vtableOffsetBits = 0L,
                    ),
                ),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testStaticField() {
        val input = "Quux:T(0,11)=s4count:/0(0,1):_ZN4Quux5countE;;;;"
        val expected = SymbolDecl.TaggedType(
            name = "Quux",
            id = LocalTypeId(0, 11),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = listOf(
                    FieldDecl(
                        name = "count",
                        type = TypeDecl.Ref(LocalTypeId(0, 1)),
                        offsetBits = 0,
                        sizeBits = 0,
                        isStatic = true,
                    ),
                ),
                methods = emptyList(),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testMethodNoParametersVoidSentinel() {
        // Method with implicit this but no explicit parameters.
        // Format: #<cls>,<ret>; (no comma after ret type signals no params)
        // stabs PDF §8.5 "Member Functions"
        val input = "Base:T(0,20)=s4method::(0,21)=#(0,20),(0,1);:_ZN4Base6methodEv;2A.;;"
        val expected = SymbolDecl.TaggedType(
            name = "Base",
            id = LocalTypeId(0, 20),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    MethodDecl(
                        name = "method",
                        mangled = "_ZN4Base6methodEv",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 21),
                            body = TypeDecl.Method(
                                cls = TypeDecl.Ref(LocalTypeId(0, 20)),
                                ret = TypeDecl.Ref(LocalTypeId(0, 1)),
                                params = emptyList(), // No explicit parameters; implicit this is in cls
                            ),
                        ),
                        access = Access.PUBLIC,
                        virt = VirtKind.NORMAL,
                        isConst = false,
                        isVolatile = false,
                        vtableOffsetBits = null,
                    ),
                ),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testMethodImplicitThisPointer() {
        // Method with implicit this pointer represented as the cls field.
        // The cls field (TypeDecl.Ref(LocalTypeId(0,20))) is a pointer to the containing class,
        // representing the implicit this argument.
        // stabs PDF §8.5 "Member Functions" notes implicit this as first argument.
        // This test verifies that cls is set correctly to the containing class type.
        val input = "Derived:T(0,30)=s8vmethod::(0,31)=#(0,30),(0,1),(0,2);:_ZN7Derived7vmethodEi;2A*0;(0,30);;;"
        val expected = SymbolDecl.TaggedType(
            name = "Derived",
            id = LocalTypeId(0, 30),
            type = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 8,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    MethodDecl(
                        name = "vmethod",
                        mangled = "_ZN7Derived7vmethodEi",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 31),
                            body = TypeDecl.Method(
                                cls = TypeDecl.Ref(LocalTypeId(0, 30)), // Implicit this: pointer to Derived
                                ret = TypeDecl.Ref(LocalTypeId(0, 1)),
                                params = listOf(TypeDecl.Ref(LocalTypeId(0, 2))), // Explicit parameter
                            ),
                        ),
                        access = Access.PUBLIC,
                        virt = VirtKind.VIRTUAL,
                        isConst = false,
                        isVolatile = false,
                        vtableOffsetBits = 0L,
                    ),
                ),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol())
    }
}
