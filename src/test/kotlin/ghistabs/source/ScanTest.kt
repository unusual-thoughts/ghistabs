package ghistabs.source

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
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
        assertEquals("size", enclosing(src, 4))
        assertEquals("grow", enclosing(src, 7))
        assertNull(enclosing(src, 2), "a class body is not a function")
    }

    @Test
    fun `a brace in a literal or a comment opens nothing`() {
        val src = """
            void f() { char c = '}'; /* } */ }
            void g() { }
        """
        assertEquals("f", enclosing(src, 1))
        assertEquals("g", enclosing(src, 2))
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
        assertEquals("vector<_Tp, _Alloc>::_M_insert_aux", enclosing(src, 5))
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
        assertEquals(listOf("f"), index(src).definitions.map { it.name })
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
        assertEquals("_Vector_alloc_base", enclosing(src, 7))
        assertEquals("get_allocator", enclosing(src, 3))
    }

    @Test
    fun `an access label does not swallow the declarator behind it`() {
        val src = """
            class A {
            public: void f() { g(); }
            private: A() : _n(0) { }
            };
        """
        assertEquals(listOf("f", "A"), index(src).definitions.map { it.name })
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
        assertEquals(
            listOf("operator()", "operator<", "operator new", "~_Less"),
            index(src).definitions.map { it.name },
        )
    }

    /** A header read mid-write, or one whose last branch a conditional left open. */
    @Test
    fun `an unclosed body runs to the end of the text`() {
        val src = """
            void f() {
              int a = 1;
        """
        assertEquals(Definition("f", 1, 2), index(src).definitions.single())
    }

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
        assertEquals(
            mapOf(
                "_Rope" to listOf(1, 5),
                "_Size" to listOf(2),
                "_Pair" to listOf(3),
                "_Cmp" to listOf(4),
                "_Kind" to listOf(6),
            ),
            index(src).declarations,
        )
    }
}
