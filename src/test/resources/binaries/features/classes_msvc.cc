#define NI __attribute__((noinline))
struct Core { int c; NI Core() : c(5) {} virtual ~Core() {} virtual int f() { return c; } };
struct Left : virtual Core { int l; NI Left() : l(1) {} virtual int g() { return l; } };
struct Right : virtual Core { int r; NI Right() : r(2) {} int f() override { return r; } };
struct Both : Left, Right { int b; NI Both() : b(3) {} int g() override { return b; } };
Core* make(int i) { if (i == 0) return new Left; if (i == 1) return new Right; if (i == 2) return new Core; return new Both; }
extern "C" int mainCRTStartup() { Core* p = make(3); int v = p->f(); delete p; return v; }
