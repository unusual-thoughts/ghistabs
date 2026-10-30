#define NI __attribute__((noinline))
struct Shape { int id; NI Shape() : id(1) {} virtual ~Shape() {} virtual int area() { return 0; } };
struct Rect : Shape { int w, h; NI Rect() : w(2), h(3) {} int area() override { return w * h; } virtual int perim() { return 2 * (w + h); } };
struct Named { const char* name; NI Named() : name("n") {} virtual ~Named() {} virtual const char* who() { return name; } };
struct Label : Rect, Named { int color; NI Label() : color(4) {} int area() override { return color; } const char* who() override { return "l"; } };
struct Core { int c; NI Core() : c(5) {} virtual ~Core() {} virtual int f() { return c; } };
struct Left : virtual Core { int l; NI Left() : l(1) {} virtual int g() { return l; } };
struct Right : virtual Core { int r; NI Right() : r(2) {} int f() override { return r; } };
struct Both : Left, Right { int b; NI Both() : b(3) {} int g() override { return b; } };
NI void* make(int i) {
    switch (i) {
    case 0: return new Shape; case 1: return new Rect; case 2: return new Named; case 3: return new Label;
    case 4: return new Core; case 5: return new Left; case 6: return new Right; default: return new Both;
    }
}
static volatile int pick = 3;
extern "C" int mainCRTStartup() { Shape* p = (Shape*)make(pick); int v = p->area(); delete p; return v; }
