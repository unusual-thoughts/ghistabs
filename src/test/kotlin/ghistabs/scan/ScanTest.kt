package ghistabs.scan

import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.Test

/** What the declarator index reads off C++ text, on the shapes libstdc++ actually contains. */
class ScanTest {
    private fun index(text: String) = DeclaratorIndex(text.trimIndent())

    private fun enclosing(text: String, line: Int) = index(text).enclosing(line)?.name

    @Test
    fun `a method's own body wins over the class holding it`() {
        val src = """
            class Widget {
              int _M_size;
            public:
              int size() const { return _M_size; }
              void grow(int by)
              {
                _M_size += by;
              }
            };
        """
        enclosing(src, 4) mustBe "size"
        enclosing(src, 7) mustBe "grow"
        enclosing(src, 2).mustBeNull("a class body is not a function")
    }

    @Test
    fun `a brace in a literal or a comment opens nothing`() {
        val src = """
            void f() { char c = '}'; /* } */ }
            void g() { }
        """
        enclosing(src, 1) mustBe "f"
        enclosing(src, 2) mustBe "g"
    }

    /** The template argument list must not be mistaken for part of the name. */
    @Test
    fun `an out-of-line template definition keeps its qualifier whole`() {
        val src = """
            template <class _Tp, class _Alloc>
            void
            vector<_Tp, _Alloc>::_M_insert_aux(iterator __position, const _Tp& __x)
            {
              ++_M_finish;
            }
        """
        enclosing(src, 5) mustBe "vector<_Tp, _Alloc>::_M_insert_aux"
        // The parameter list comes along, whitespace collapsed, for the heads gcc left without one.
        index(src).definitions.single().params mustBe "iterator __position, const _Tp& __x"
    }

    @Test
    fun `control statements, type bodies and namespaces are not definitions`() {
        val src = """
            namespace std {
            struct _Tag { int a; };
            enum _Kind { _Small, _Large };
            void f(int x) {
              if (x) {
                for (int i = 0; i < x; ++i) { --x; }
              } else {
                switch (x) { default: break; }
              }
            }
            }
        """
        index(src).definitions.map { it.name } mustBe listOf("f")
    }

    /**
     * stl_vector.h L112 in gcc 3.2.3: `{}` on its own line under an initialiser list. §44's Python
     * heuristic named it `_M_start`, the last thing before a `(` — this must name the constructor.
     */
    @Test
    fun `a constructor initialiser list is not a function`() {
        val src = """
            class _Vector_alloc_base {
            public:
              allocator_type get_allocator() const { return allocator_type(); }

              _Vector_alloc_base(const allocator_type&)
                : _M_start(0), _M_finish(0), _M_end_of_storage(0)
              {}
            protected:
              _Tp* _M_start;
            };
        """
        enclosing(src, 7) mustBe "_Vector_alloc_base"
        enclosing(src, 3) mustBe "get_allocator"
    }

    @Test
    fun `an access label does not swallow the declarator behind it`() {
        val src = """
            class A {
            public: void f() { g(); }
            private: A() : _n(0) { }
            };
        """
        index(src).definitions.map { it.name } mustBe listOf("f", "A")
    }

    @Test
    fun `operators and destructors are named as they are spelled`() {
        val src = """
            struct _Less {
              bool operator()(const int& a, const int& b) const { return a < b; }
              bool operator<(const _Less&) { return false; }
              void* operator new(size_t __n) { return malloc(__n); }
              ~_Less() throw() { }
            };
        """
        index(src).definitions.map { it.name } mustBe listOf("operator()", "operator<", "operator new", "~_Less")
    }

    /** A header read mid-write, or one whose last branch a conditional left open. */
    @Test
    fun `an unclosed body runs to the end of the text`() {
        val src = """
            void f() {
              int a = 1;
        """
        index(src).definitions.single() mustBe Definition("f", "", 1, 2)
    }

    /** `class _Rope;` is not one: a forward declaration would let `stringfwd.h` outrank the header
     *  the class is actually in. */
    @Test
    fun `declarations are the lines a name is declared on`() {
        val src = """
            class _Rope;
            typedef unsigned long _Size;
            typedef struct { int a; } _Pair;
            typedef int (*_Cmp)(const void*, const void*);
            struct _Rope { int _M_c; };
            enum _Kind { _Small };
        """
        index(src).declarations mustBe mapOf(
            "_Rope" to listOf(5),
            "_Size" to listOf(2),
            "_Pair" to listOf(3),
            "_Cmp" to listOf(4),
            "_Kind" to listOf(6),
        )
    }

    /** The extent an included file is given (§43) — a trailing newline does not add a line to it. */
    @Test
    fun `the line count is the file's last line`() {
        DeclaratorIndex("void f() { }\nvoid g() { }\n").lineCount mustBe 2
        DeclaratorIndex("void f() { }\nvoid g() { }").lineCount mustBe 2
    }
}
