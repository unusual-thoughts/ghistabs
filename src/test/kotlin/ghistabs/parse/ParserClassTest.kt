package ghistabs.parse

import ghistabs.parse.TypeDecl.Struct.Base
import ghistabs.parse.TypeDecl.Struct.Field
import ghistabs.parse.TypeDecl.Struct.Method
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
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Foo",
            id = LocalTypeId(0, 5),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 8,
                bases = emptyList(),
                fields = listOf(
                    Field(
                        "x",
                        TypeDecl.Ref(LocalTypeId(0, 1)),
                        offsetBits = 0,
                        sizeBits = 32,
                        isStatic = false,
                        access = Access.PUBLIC,
                        mangled = null,
                    ),
                    Field(
                        "y",
                        TypeDecl.Ref(LocalTypeId(0, 1)),
                        offsetBits = 32,
                        sizeBits = 32,
                        isStatic = false,
                        access = Access.PUBLIC,
                        mangled = null,
                    ),
                ),
                methods = emptyList(),
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testSingleInheritanceNonVirtual() {
        val input = "Bar:T(0,6)=s4!1,020,(0,5);;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Bar",
            id = LocalTypeId(0, 6),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases =
                listOf(
                    Base(
                        type = TypeDecl.Ref(LocalTypeId(0, 5)),
                        isVirtual = false,
                        access = Access.PUBLIC,
                        offsetBits = 0,
                    ),
                ),
                fields = emptyList(),
                methods = emptyList(),
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testClassWithVTablePointerMarker() {
        // `~%<id>;` is the LAST section, after the field-list terminator — not right after size.
        val input = "Baz:T(0,7)=s8;~%(0,8);"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Baz",
            id = LocalTypeId(0, 7),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 8,
                bases = emptyList(),
                fields = emptyList(),
                methods = emptyList(),
                vptrBasetype = TypeDecl.Ref(LocalTypeId(0, 8)),
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testDtorPseudoNameTrailingSpaceStripped() {
        // gcc emits special-member pseudo-names with a space before `::` (`__comp_dtor ::`).
        // The space must not survive into the name, or the vtable field and its FD type diverge.
        val input = "Q:T(0,9)=s4__comp_dtor ::(0,10):_ZN1QD1Ev;2A*0;(0,9);;;"
        val method = (Parser(input).parseSymbol().expectOk() as SymbolDecl.NamedType).type
            .let { it as TypeDecl.Struct }.methods.single()
        assertEquals("__comp_dtor", method.name)
    }

    @Test
    fun testMethodWithMangledSymbol() {
        val input = "Qux:T(0,9)=s4doIt::(0,10)=#(0,9),(0,1),(0,2);:_ZN3Qux4doItEi;2A.;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Qux",
            id = LocalTypeId(0, 9),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    Method(
                        name = "doIt",
                        mangled = "_ZN3Qux4doItEi",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 10),
                            inner = TypeDecl.Method(
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
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testBaseClassAsFieldWithQualifiedTemplateName() {
        // gcc 3.4.5 spells a base class out as a pseudo-field whose name carries qualified
        // template args (`CryptoPP::word16`). The `::` inside `<...>` must not be read as a
        // method marker — the field name runs to the `:` after the closing `>`.
        val input = "AllocatorWithCleanup<CryptoPP::word16>:T(55,4)=s1AllocatorBase<CryptoPP::word16>:(55,3),0,64;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "AllocatorWithCleanup<CryptoPP::word16>",
            id = LocalTypeId(55, 4),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 1,
                bases = emptyList(),
                fields = listOf(
                    Field(
                        "AllocatorBase<CryptoPP::word16>",
                        TypeDecl.Ref(LocalTypeId(55, 3)),
                        offsetBits = 0,
                        sizeBits = 64,
                        isStatic = false,
                        access = Access.PUBLIC,
                        mangled = null,
                    ),
                ),
                methods = emptyList(),
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testOperatorMethodWithAngleBrackets() {
        // `operator<<` keeps its angle brackets as operator tokens; they must not open
        // template depth (which would swallow the `::` method marker).
        val input = "Str:T(0,9)=s1operator<<::(0,10)=#(0,9),(0,1),(0,2);:_ZN3StrlsEi;2A.;;"
        val parsed = Parser(input).parseSymbol().expectOk() as SymbolDecl.NamedType
        val struct = parsed.type as TypeDecl.Struct
        assertEquals(1, struct.methods.size)
        assertEquals("operator<<", struct.methods.single().name)
    }

    @Test
    fun testVirtualMethod() {
        val input = "Qux:T(0,9)=s4doIt::(0,10)=#(0,9),(0,1),(0,2);:_ZN3Qux4doItEi;2A*0;(0,9);;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Qux",
            id = LocalTypeId(0, 9),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    Method(
                        name = "doIt",
                        mangled = "_ZN3Qux4doItEi",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 10),
                            inner = TypeDecl.Method(
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
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testStaticField() {
        val input = "Quux:T(0,11)=s4count:/0(0,1):_ZN4Quux5countE;;;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Quux",
            id = LocalTypeId(0, 11),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = listOf(
                    Field(
                        name = "count",
                        type = TypeDecl.Ref(LocalTypeId(0, 1)),
                        offsetBits = 0,
                        sizeBits = 0,
                        isStatic = true,
                        access = Access.PRIVATE,
                        // The member's linkage name: stabs' only link from a static member to its
                        // emitted symbol, since these carry no `G`/`S` address stab of their own.
                        mangled = "_ZN4Quux5countE",
                    ),
                ),
                methods = emptyList(),
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    /**
     * Without `-gstabs+`, gcc emits a static data member as the bare `name:type,0,0` rather than
     * the `:mangled` form — recognized by offset and size both being zero (gcc-4.2.1 libstdc++).
     */
    @Test
    fun testStaticFieldGstabsNoExtensions() {
        val input = "Quux:T(0,11)=s4id:(0,1),0,0;;;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Quux",
            id = LocalTypeId(0, 11),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = listOf(
                    Field(
                        name = "id",
                        type = TypeDecl.Ref(LocalTypeId(0, 1)),
                        offsetBits = 0,
                        sizeBits = 0,
                        isStatic = true,
                        access = Access.PUBLIC,
                        mangled = null,
                    ),
                ),
                methods = emptyList(),
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testMethodNoParametersVoidSentinel() {
        // Method with implicit this but no explicit parameters.
        // Format: #<cls>,<ret>; (no comma after ret type signals no params)
        // stabs PDF §8.5 "Member Functions"
        val input = "Base:T(0,20)=s4method::(0,21)=#(0,20),(0,1);:_ZN4Base6methodEv;2A.;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Base",
            id = LocalTypeId(0, 20),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 4,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    Method(
                        name = "method",
                        mangled = "_ZN4Base6methodEv",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 21),
                            inner = TypeDecl.Method(
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
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testMethodImplicitThisPointer() {
        // Method with implicit this pointer represented as the cls field.
        // The cls field is the type as it appears in the stabs method descriptor (#<cls>,...).
        // In this test, (0,30) is a back-reference to the containing class itself.
        // Per the stabs PDF §8.5 "Member Functions", the first parameter (implicit this) is the
        // containing class; the AST stores the parsed type as-is (not wrapped in Pointer).
        // stabs PDF §8.5 "Member Functions" notes implicit this as first argument.
        // This test verifies that cls is set correctly to the containing class type reference.
        val input = "Derived:T(0,30)=s8vmethod::(0,31)=#(0,30),(0,1),(0,2);:_ZN7Derived7vmethodEi;2A*0;(0,30);;;"
        val expected = SymbolDecl.NamedType(
            kind = TypeNameKind.TAG,
            name = "Derived",
            id = LocalTypeId(0, 30),
            type = TypeDecl.Struct(
                rawKind = AggrKind.STRUCT,
                sizeBytes = 8,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(
                    Method(
                        name = "vmethod",
                        mangled = "_ZN7Derived7vmethodEi",
                        signature = TypeDecl.InlineDef(
                            id = LocalTypeId(0, 31),
                            inner = TypeDecl.Method(
                                cls = TypeDecl.Ref(LocalTypeId(0, 30)), // Implicit this: the containing class
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
                vptrBasetype = null,
            ),
        )
        assertEquals(expected, Parser(input).parseSymbol().expectOk())
    }

    @Test
    fun testTildeFieldFollowsMethods() {
        // `~%` is the LAST section — after member functions, not after size. Corpus shape:
        // `<method>;;~%<owner>;`. Regression for the years-long misparse that read it after size.
        val input = "P:T(0,5)=s8vmethod::(0,31)=#(0,5),(0,1),(0,2);:_ZN1P7vmethodEi;2A*0;(0,5);;;~%(0,9);"
        val struct = (Parser(input).parseSymbol().expectOk() as SymbolDecl.NamedType).type as TypeDecl.Struct
        assertEquals(TypeDecl.Ref(LocalTypeId(0, 9)), struct.vptrBasetype)
        assertEquals(1, struct.methods.size)
    }

    @Test
    fun testTildeFieldInlineForwardXref() {
        // The `~%` target is a full read_type, not just an id: RTTI/exception classes emit an inline
        // forward-xref `(cu,n)=xsName:`. Regression for the guard dropping the whole class on `=`.
        val input = "underflow_error:T(0,5)=s8;~%(0,6)=xstype_info:;"
        val struct = (Parser(input).parseSymbol().expectOk() as SymbolDecl.NamedType).type as TypeDecl.Struct
        assertEquals(
            TypeDecl.InlineDef(LocalTypeId(0, 6), TypeDecl.XRef(AggrKind.STRUCT, "type_info")),
            struct.vptrBasetype,
        )
    }

    /**
     * `?` in a method trailer is a *static* member function (gdb stabsread.c `case '?'`), not a
     * pure virtual. Corpus shape from unbouniaf's `FileSystemImage`: a static's signature is a
     * plain `f(ret)`, never a `#(cls,…)` method type, and it takes no `this`.
     */
    @Test
    fun testStaticMemberFunction() {
        val input = "FileSystemImage:T(0,5)=s40" +
            "isValidMagic::(0,21)=f(0,9):_ZN15FileSystemImage12isValidMagicEm;0A?;;;"
        val struct = (Parser(input).parseSymbol().expectOk() as SymbolDecl.NamedType).type as TypeDecl.Struct
        val m = struct.methods.single()
        assertEquals(VirtKind.STATIC, m.virt)
        assertEquals(Access.PRIVATE, m.access)
        assertEquals(
            TypeDecl.InlineDef(LocalTypeId(0, 21), TypeDecl.FunctionT(TypeDecl.Ref(LocalTypeId(0, 9)), emptyList())),
            m.signature,
        )
        assertEquals(false, m.isConst)
        assertEquals(null, m.vtableOffsetBits)
    }

    /** cv-qualifier letter: `A` none, `B` const, `C` volatile, `D` const volatile. */
    @Test
    fun testMethodCvQualifierLetters() {
        fun virtOf(letter: Char): Method<LocalTypeId> {
            val input = "S:T(0,5)=s4f::(0,10)=#(0,5),(0,1);:_ZNK1S1fEv;2$letter.;;;"
            return (
                (
                    Parser(
                        input,
                    ).parseSymbol().expectOk() as SymbolDecl.NamedType
                    ).type as TypeDecl.Struct
                ).methods.single()
        }
        assertEquals(false to false, virtOf('A').let { it.isConst to it.isVolatile })
        assertEquals(true to false, virtOf('B').let { it.isConst to it.isVolatile })
        assertEquals(false to true, virtOf('C').let { it.isConst to it.isVolatile })
        assertEquals(true to true, virtOf('D').let { it.isConst to it.isVolatile })
    }

    /**
     * Without `-gstabs+` gcc has no boolean descriptor to emit, so it writes `bool` as an enum over
     * False/True (`gcc/dbxout.c`, the `else` of `use_gnu_debug_info_extensions`) and the width is
     * lost. Decode it to what the extension branch would have written, so it does not reach Ghidra
     * as a sizeof(int) enum.
     */
    @Test
    fun testBoolSpelledAsEnumDecodesToTheBuiltin() {
        val enumForm = (Parser("bool:t(0,4)=eFalse:0,True:1,;").parseSymbol().expectOk() as SymbolDecl.NamedType).type
        val extensionForm = TypeDecl.WithSizeAttr<LocalTypeId>(8, TypeDecl.Builtin(-16))
        assertEquals(extensionForm, enumForm)
    }

    /**
     * gcc emits the same spelling unnamed and inline, so the decode keys on the members alone — a
     * name gate converted only the typedef and orphaned the inline copy from the content merge that
     * had been naming it, leaving 56 bool variables on an anonymous type. A user-written
     * `enum Flag { False, True }` is therefore read as bool as well; gcc's spelling is identical.
     */
    @Test
    fun testTheSameSpellingDecodesWhereverItAppears() {
        val decoded = TypeDecl.WithSizeAttr<LocalTypeId>(8, TypeDecl.Builtin(-16))
        val named = (Parser("bool:t(0,4)=eFalse:0,True:1,;").parseSymbol().expectOk() as SymbolDecl.NamedType).type
        assertEquals(decoded, named)
        // An inline `(cu,n)=<body>` keeps its id binding; the body is what must match.
        val inlineUnnamed = (Parser("f:F(0,8)=eFalse:0,True:1,;").parseSymbol().expectOk() as SymbolDecl.Function).type
        assertEquals(TypeDecl.InlineDef(LocalTypeId(0, 8), decoded), inlineUnnamed)
    }

    @Test
    fun testUnconsumedStructSectionRejected() {
        // A struct section we don't handle must fail loudly, not get silently dropped as
        // trailing input (the leniency that hid `~%`).
        Parser("X:T(0,5)=s4;Zjunk").parseSymbol().expectError()
    }
}
