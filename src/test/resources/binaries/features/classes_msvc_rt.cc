#include <stddef.h>
static char heap[4096]; static size_t used;
// Exported, so the stripped binary still names them and the class pass reads allocation sizes off them.
__declspec(dllexport) void* operator new(size_t n) { void* p = heap + used; used += (n + 7) & ~7u; return p; }
__declspec(dllexport) void operator delete(void*) noexcept {}
__declspec(dllexport) void operator delete(void*, size_t) noexcept {}
extern "C" const void* const type_info_vftable[2] __asm__("??_7type_info@@6B@") = {0, 0};
