// One small C++ program touching as many stab forms as fits: builtins, typedefs, enums, bitfields,
// unions (one with methods), arrays, function and member pointers, classes with access/static/const/
// virtual/pure members, single/multiple/virtual inheritance, templates, nested types, by-value struct
// return, varargs, register/static locals, nested scopes and exceptions. Under the MSVC ABI: a vptr
// splitting a class's bases, a vtordisp in front of a virtual base, a class whose only vftable is its
// virtual base's. Then cv-qualifiers on fields, pointers and methods, references as members, static
// members and methods, overloads, conversion and subscript operators, friends, nested and local classes,
// private/protected/virtual-function-only bases, an empty base, anonymous unions and structs, enum
// bitfields, every builtin, function-returning-function pointers, extern "C", a global constructor and,
// past gcc 2.7, namespaces, member templates, explicit specialisations, mutable and explicit.
#include <stdarg.h>
#include <stdio.h>

#if defined(__GNUC__) && __GNUC__ == 2 && __GNUC_MINOR__ < 8
#define explicit
#define mutable
#else
#define MODERN 1
#endif

typedef unsigned char u8;
typedef long long i64;
typedef int (*Callback)(int, void *);
enum Color { RED, GREEN = 4, BLUE = -1 };
struct Flags { unsigned ro : 1, hidden : 1, mode : 3; signed prio : 4; };
union Value { int i; float f; char bytes[4]; };
struct Point { short x, y; };

class Shape {
public:
    enum Kind { CIRCLE, SQUARE };
    Shape(Kind k) : kind(k) { ++count; }
    virtual ~Shape() {}
    virtual double area() const = 0;
    virtual const char *name() const { return "shape"; }
    Kind kind;
    static int count;
protected:
    Point origin;
private:
    Flags flags;
};

class Circle : public Shape {
public:
    Circle(double r) : Shape(CIRCLE), r(r) {}
    double area() const { return 3.14159 * r * r; }
    const char *name() const;
private:
    double r;
};

struct Base { int id; };
struct Left : virtual Base { int l; };
struct Right : virtual Base { int r; };
struct Named { Named() { label[0] = 0; label[7] = 0; } virtual ~Named() {} char label[8]; };
struct Diamond : Left, Right, Named {
    int d;
    Diamond() : d(0) {}
    Diamond &operator+=(int k) { d += k; return *this; }
};

struct Rect : Shape {
    int w, h;
    Rect() : Shape(SQUARE), w(2), h(3) {}
    double area() const { return w * h; }
    virtual int perim() const { return 2 * (w + h); }
};
struct Label : Rect, Named {
    int color;
    Label() : color(4) {}
    double area() const { return color; }
};
struct Core { int c; Core() : c(5) {} virtual ~Core() {} virtual int f() { return c; } };
struct Up : virtual Core { int u; Up() : u(1) {} virtual int g() { return u; } };
struct Down : virtual Core { int dn; Down() : dn(2) {} int f() { return dn; } };
struct Both : Up, Down { int b; Both() : b(3) {} int g() { return b; } };

struct Empty {};
struct Quals : Empty {
    const int ci;
    volatile int vi;
    const volatile unsigned short cvs;
    int &ref;
    const char *const *names;
    volatile Point *vp;
    mutable int hits;
    static const int LIMIT = 3;
    static int instances;
    typedef int Cell;
    struct Inner { Cell row, col; };
    Inner where;
    union { int whole; struct { short lo, hi; } part; };
    enum Mode { OFF, ON } mode : 2;
    explicit Quals(int &r) : ci(1), vi(2), cvs(3), ref(r), names(0), vp(0), hits(0), mode(ON) {
        ++instances; where.row = where.col = 0; whole = 0;
    }
    Quals(const Quals &o) : Empty(), ci(o.ci), vi(o.vi), cvs(o.cvs), ref(o.ref), names(o.names), vp(o.vp), hits(0),
        mode(o.mode) { ++instances; where = o.where; whole = o.whole; }
    int get() { return ci; }
    int get() const { return hits + ci; }
    int get() volatile { return vi; }
    int get() const volatile { return cvs; }
    int peek(int i, int j = 2) const { return i * j; }
    int peek(double d) const { return (int)d; }
    static int count() { return instances; }
    operator int() const { return ci + vi; }
    int operator[](int i) const { return i + ci; }
    Quals &operator=(const Quals &o) { vi = o.vi; return *this; }
    friend int poke(Quals &q);
private:
    Quals();
};
int Quals::instances;
int poke(Quals &q) { return q.vi = q.ci + 1; }

struct Logger { virtual void log(const char *) {} virtual ~Logger() {} };
class Secret : private Logger, protected Point {
public:
    Secret() { x = 1; y = 2; }
    int sum() const { return x + y; }
};

struct Builtins {
    bool b; char c; signed char sc; unsigned char uc; wchar_t wc; short s; unsigned short us;
    int i; unsigned u; long l; unsigned long ul; long long ll; unsigned long long ull;
    float f; double d; long double ld;
};

typedef int (*Unary)(int);
static int twice(int v) { return 2 * v; }
static Unary pick(int which) { return which ? twice : 0; }
static int (*(*g_picker)(int))(int) = pick;
static Unary g_table[2] = { twice, 0 };
extern "C" int c_linkage(int v) { return v + 1; }

struct Boot { int ready; Boot() : ready(42) {} };
static Boot g_boot;

#ifdef MODERN
namespace outer {
    int depth = 1;
    namespace inner { struct Deep { int v; int get() const { return v + depth; } }; }
}
struct Box {
    template <class T> T as(T t) const { return t; }
};
template <class T> struct Traits { enum { size = sizeof(T) }; };
template <> struct Traits<void> { enum { size = 0 }; };
#endif

static int extras(int n)
{
    struct Local { int v; int twice() const { return 2 * v; } } loc = { n };
    int r = 0;
    Quals q(r);
    const Quals cq(q);
    volatile Quals &vq = q;
    const volatile Quals &cvq = q;
    Secret sec;
    Builtins bi = { true, 'c', -1, 1, L'w', -2, 2, -3, 3, -4, 4, -5, 5, 1.5f, 2.5, 3.5L };
    int k = q.get() + cq.get() + vq.get() + cvq.get() + q.peek(2) + q.peek(1.5) + Quals::count() + (int)q + q[1] + poke(q);
    k += sec.sum() + loc.twice() + bi.i + g_picker(1)(3) + g_table[0](1) + c_linkage(1) + g_boot.ready;
#ifdef MODERN
    outer::inner::Deep deep = { 2 };
    Box box;
    k += deep.get() + box.as(1) + Traits<int>::size + Traits<void>::size;
#else
    k += 3 + 1 + 4;
#endif
    return k;
}

template <class T, int N> struct Stack {
    struct Iter { const Stack *s; int i; };
    T items[N];
    int top;
    Stack() : top(0) {}
    void push(const T &t) { items[top++] = t; }
    T pop() { return items[--top]; }
};

template <class T> T max2(T a, T b) { return a > b ? a : b; }

int Shape::count;
static Color g_color = GREEN;
Value g_val;
const char *const g_names[] = { "red", "green" };
volatile int g_ticks;
double matrix[2][3];
long double g_ld = 1.5L;
Callback g_cb;

const char *Circle::name() const { return "circle"; }

static int sum(int n, ...)
{
    va_list ap;
    int s = 0;
    va_start(ap, n);
    while (n--)
        s += va_arg(ap, int);
    va_end(ap);
    return s;
}

Point mid(Point a, Point b) { Point p = { (a.x + b.x) / 2, (a.y + b.y) / 2 }; return p; }

static int probe(Circle &c, int n)
{
    try { if (n > 5) throw c; } catch (Shape &e) { return e.kind; }
    return -1;
}

static int layouts(int n)
{
    Label l;
    Both b;
    Down dn;
    Core *c = n > 1 ? (Core *)&b : (Core *)&dn;
    return l.perim() + (int)l.area() + c->f() + b.g();
}

static int bump(int k, void *ctx) { static int calls; return k + *(int *)ctx + ++calls; }

union Word {
    Word(unsigned int v) : u(v) {}
    unsigned char lo() const { return b[0]; }
    unsigned short hi() const { return h[1]; }
    unsigned int u;
    unsigned char b[4];
private:
    unsigned short h[2];
};

int main(int argc, char **argv)
{
    register int i;
    Circle c(2.0);
    Shape &s = c;
    double (Shape::*pmf)() const = &Shape::area;
    int Base::*pm = &Base::id;
    Diamond d;
    Stack<Point, 2> ps;
    Stack<int, 4>::Iter it = { 0, 0 };
    union { int as_int; float as_float; } pun;
    Word w(0x3f800000u);
    d.*pm = 7;
    d += 3;
    for (i = 0; i < 2; i++) {
        Point p = { i, -i };
        ps.push(p);
        { u8 col = (u8)(i + 1); matrix[i][col] = (s.*pmf)(); }
    }
    Point m = mid(ps.pop(), ps.pop());
    g_cb = bump;
    pun.as_float = 1.0f;
    i64 big = (i64)pun.as_int << 20;
    printf("%s %g %d %d %lld %d %d %d %d %d %d %d %s\n", s.name(), c.area(), max2(m.x, m.y), sum(3, 1, 2, 3),
           big, g_cb(1, &i), it.i, probe(c, argc), w.lo(), w.hi(), layouts(argc), extras(argc), argv[0]);
    return Shape::count + g_color + d.d;
}
