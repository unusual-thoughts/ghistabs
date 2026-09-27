// One small C++ program touching as many stab forms as fits: builtins, typedefs, enums, bitfields,
// unions (one with methods), arrays, function and member pointers, classes with access/static/const/
// virtual/pure members, single/multiple/virtual inheritance, templates, nested types, by-value struct
// return, varargs, register/static locals, nested scopes and exceptions.
#include <stdarg.h>
#include <stdio.h>

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
struct Named { virtual ~Named() {} char label[8]; };
struct Diamond : Left, Right, Named {
    int d;
    Diamond() : d(0) {}
    Diamond &operator+=(int k) { d += k; return *this; }
};

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
    printf("%s %g %d %d %lld %d %d %d %d %d %s\n", s.name(), c.area(), max2(m.x, m.y), sum(3, 1, 2, 3),
           big, g_cb(1, &i), it.i, probe(c, argc), w.lo(), w.hi(), argv[0]);
    return Shape::count + g_color + d.d;
}
