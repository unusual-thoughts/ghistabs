// Pointer to data member and by-value class parameters passed by invisible reference.
struct A { int x; double d; char *p; };

int A::*pmi = &A::x;
double A::*pmd = &A::d;

struct B { int A::*f; char *A::*g; };
B b = { &A::x, &A::p };

int deref(A &a, int A::*m) { return a.*m; }

// A copy constructor forces pass-by-invisible-reference: `v`-less stack form and, with regparm, `a`.
struct C { int v; C(const C &o) : v(o.v) {} C() : v(0) {} ~C() {} };
int byval(C c) { return c.v; }
int __attribute__((regparm(3))) byreg(C c, int k) { return c.v + k; }

int main() {
    A a = { 1, 2.0, 0 };
    C c;
    return (b.f == pmi) + deref(a, pmi) + byval(c) + byreg(c, 1);
}
