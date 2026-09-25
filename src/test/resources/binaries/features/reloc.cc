// A static in each of .data, .bss and .rodata, a function-local static, and a static function: in a
// relocatable object each is `.rel.stab` against its section plus an offset, the globals against a symbol.
static int counter = 3;
static long zeroed;
static const short table[4] = { 1, 2, 3, 4 };

static int bump(int by) { static int calls; ++calls; return counter += by; }

int total(int n) { return bump(n) + table[n & 3] + (int)zeroed; }
