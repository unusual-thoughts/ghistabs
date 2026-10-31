// The bits of the MSVC runtime hello.cc needs, for a link with no CRT: enough to build, not to run.
#include <stddef.h>
static char heap[4096]; static size_t used;
// Exported, so the stripped binary still names them and the class pass reads allocation sizes off them.
__declspec(dllexport) void* operator new(size_t n) { void* p = heap + used; used += (n + 7) & ~7u; return p; }
__declspec(dllexport) void operator delete(void*) noexcept {}
__declspec(dllexport) void operator delete(void*, size_t) noexcept {}
extern "C" const void* const type_info_vftable[2] __asm__("??_7type_info@@6B@") = {0, 0};
extern "C" int _fltused = 0;
extern "C" int printf(const char*, ...) { return 0; }
extern "C" void* memset(void* p, int c, size_t n) { for (size_t i = 0; i < n; i++) ((char*)p)[i] = (char)c; return p; }
extern "C" int _purecall() { for (;;) {} }
extern "C" void __stdcall _CxxThrowException(void*, void*) { for (;;) {} }
extern "C" int __CxxFrameHandler3() { return 1; }
