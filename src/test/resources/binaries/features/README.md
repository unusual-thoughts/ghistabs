# Feature fixtures

Small single-purpose binaries, kept out of the fixture matrix (which only scans the parent directory)
and exercised by their own integration test.

| Fixture | Compiler | Built in | Test |
|---|---|---|---|
| `ptrmem_elf_gcc295` | gcc 2.95.2, i386 | Debian potato (`~/machines/potato`, systemd-nspawn) | `MemberPointerIntegrationTest` |
| `ptrmem_elf64_gcc12` | gcc 12.2.0, x86-64 | `docker run debian:bookworm` + `apt-get install g++` | `MemberPointerIntegrationTest` |
| `reloc_elf_gcc295.o` | gcc 2.95.2, i386 | Debian potato (`~/machines/potato`, systemd-nspawn) | `RelocatableObjectIntegrationTest` |
| `reloc_elf64_gcc12.o` | gcc 12.2.0, x86-64 | `docker run debian:bookworm` + `apt-get install g++` | `RelocatableObjectIntegrationTest` |
| `hello_elf_gcc272` | gcc 2.7.2.3, i386, static | natively, `~/machines/old-gcc` (see `elfbuild/build.sh`), `-fhandle-exceptions` | — |
| `hello_elf_gcc295` | gcc 2.95.2, i386 | Debian potato (`~/machines/potato`, systemd-nspawn) | — |
| `hello_elf_gcc32` | gcc 3.2.3, i386 | chroot of sarge's `libc6`, `libc6-dev`, `binutils` and `dash` plus Debian's `gcc-3.2`/`g++-3.2` 3.2.3-9 debs (snapshot.debian.org; sarge dropped 3.2), `g++-3.2` run from `/out` | — |
| `hello_elf_gcc33`, `_gcc34` | gcc 3.3.5 / 3.4.4, i386 | `docker run --platform linux/386 debian/eol:sarge` (`g++`, `g++-3.4`) | — |
| `hello_elf_gcc41` … `_gcc8` | gcc 4.1.2 / 4.3.2 / 4.4.5 / 4.7.2 / 4.9.2 / 6.3.0 / 8.3.0, i386 | `debian/eol:` etch / lenny / squeeze / wheezy / jessie / stretch / buster | — |
| `hello_elf_gcc10`, `_gcc12` | gcc 10.2.1 / 12.2.0, i386 PIE | `debian/eol:bullseye` (security via its snapshot.debian.org line), `debian:bookworm` | — |
| `latetypedef_elf64_gcc9`, `_gcc10`, `_gcc12` | gcc 9.5.0 / 10.5.0 / 12.4.0, x86-64 PIE | Ubuntu 24.04 `apt-get install gcc-9 gcc-10 gcc-12` | `LateTypedefIntegrationTest` |
| `hello_gcc345.exe`, `hello_gcc421.exe` | MinGW gcc 3.4.5 / 4.2.1, PE32 | `debian/eol:etch` / `lenny`, package `mingw32`, `-static`; 4.2.1 then `objcopy --remove-section='.debug_*'` | — |
| `hello_gcc323_fullstabs.exe` | MinGW gcc 3.2.3, PE32, SJLJ | the MinGW-3.1.0-1 bundle rebuilt from its own sources in a sarge i386 chroot, every target library with stabs: `build_mingw323.sh`, then `mingw32-g++ -gstabs+ -O0 -static` | — |
| `classes_msvc_clang.exe` | clang 18, i686-pc-windows-msvc, `-O1`, stripped | `clang --target=i686-pc-windows-msvc -O1 -fno-exceptions -c` of `classes_msvc.cc` and `classes_msvc_rt.cc`, then `lld-link /nodefaultlib /entry:mainCRTStartup /subsystem:console` | `MsvcClassStructsIntegrationTest` |
| `hello_msvc_clang.exe` | clang 18, i686-pc-windows-msvc, `-O0`, stripped | `clang --target=i686-pc-windows-msvc -std=c++98 -Wno-c++11-narrowing -O0 -Imsvc_stub -c hello.cc`, `clang --target=i686-pc-windows-msvc -O0 -fno-builtin -c hello_msvc_rt.cc`, then `lld-link /nodefaultlib /entry:main /subsystem:console /brepro` | `MsvcClassStructsIntegrationTest` |

The `latetypedef` set from `latetypedef.c` + `latetypedef.h` with `gcc-N -gstabs+ -O0 -fdebug-prefix-map=$PWD=/src
latetypedef.c`. From gcc 10, `-feliminate-unused-debug-symbols` is on by default: each header struct is defined
inline at its first use and named by a bare `Name:t(id)` afterwards, with the header's line and no N_BINCL. gcc 9
opens `N_BINCL latetypedef.h` and defines them there (render-backlog §85).

The `ptrmem` pair from `ptrmem.cc` with `g++ -gstabs+ -O0 ptrmem.cc -o <fixture>`, linked.

The `reloc` pair from `reloc.cc` with `g++ -gstabs+ -O0 -c reloc.cc`, left relocatable: every addressed
stab is 0 in the file plus a `.rel.stab` entry, against the function's symbol for a global function and
against `.text`/`.data`/`.bss`/`.rodata` plus an offset for everything static. i386 is REL, so that
offset sits in place (`zeroed` is `.bss`+4); x86-64 is RELA, so it is the addend. Ghidra's ELF loader
applies both to the `.stab` block.

`ptrmem.cc` straddles gcc 3.4.0's change to `build_ptrmem_type`, which stopped wrapping OFFSET_TYPE in a
POINTER_TYPE: gcc 2.95 writes `int A::*` as `*@A,int`, gcc 12 as `@A,int`. The `regparm` by-value class
parameter is `c:a…` under 2.95 (address in a register) and an explicit `&` reference under 12, which
ignores `regparm` on x86-64.

The `hello_*` set is one source, `hello.cc`, built with `g++ -gstabs+ -O0 hello.cc -o <fixture>` across every
gcc generation that still emits stabs, all i386 so only the compiler varies. It packs most stab forms into one
screen: typedefs, enums, bitfields, unions, multi-dim arrays, function/data/method pointers, access specifiers,
static/const/virtual/pure members, single + multiple + virtual inheritance, templates with nested types, a
union class (constructor, const methods, a private member),
by-value struct return, varargs, register/static locals, nested scopes and a throw/catch. Every build prints
the same line and exits 8. The try/catch lives in its own function because gcc 2.7.2.3 ICEs
(`unrecognizable insn`) on EH inside `main` next to a `register` local.

gcc 3.1 to 3.3 open every CU with an N_BINCL of the main file, spelled as given on the command line (`hello.cc`): `c-lex.c` calls the `start_source_file` debug hook for the primary file before parsing. gcc 3.4 dropped that call, so `hello_elf_gcc32` and `_gcc33` have it and no other build does.

`hello_gcc323_fullstabs.exe` is the one PE build whose runtime carries stabs too, not just `hello.cc`. It is built with
the MinGW-3.1.0-1 bundle, i.e. gcc-3.2.3-20030504-1 (MinGW-patched), binutils 2.13.90-20030111-1, mingw-runtime 3.1 and
w32api 2.4, the toolchain behind real-world MinGW 3.2.3 binaries.
`build_mingw323.sh` rebuilds that bundle from the sources on mingw.org's SourceForge `OldFiles` as a Linux cross, following
MinGW's own `gcc-3.2.3-build.sh`, with `-gstabs+` added to libgcc (`LIBGCC2_DEBUG_CFLAGS`, so the SJLJ unwinder in
`unwind-sjlj.c` is described), libsupc++/libstdc++ and the runtime. Optimisation is left at what MinGW shipped, so the code
is MinGW's: against the bundle's own libraries every function in libgcc (135), libsupc++ (220), libstdc++ (1874, all but
`stl-inst.o`'s, which embed an `__FILE__` string), libmingwex (453), libmoldname and `crt2.o` comes out instruction-for-instruction
identical, modulo `(%a,%b,1)` operand order and anonymous-namespace hash suffixes.
Getting there took three things the bundle's scripts don't say:

- mingw-runtime 3.1 was compiled `-O2 -mcpu=i686`: `isascii`'s `push/mov/xor/test/pop/sete` schedule is gcc 3.2.3
  `-mcpu=i686` and nothing else (3.3.1 is `push/xor/mov`, plain 3.2.3 is `sete; and $0xff`).
- libstdc++ was configured natively; a cross configure turns off `HAVE_MODFF`, `HAVE_EXPF`, `HAVE___BUILTIN_*` etc. and
  adds libmath stubs, so the script turns the binary release's installed `bits/c++config.h` back into the `config.h` it
  was generated from. (The installed header's `_GLIBCPP_USE_C99 (__MINGW32_MAJOR_VERSION >= 3)` is a
  hand edit after the build, with a `c++config.h.$$$` backup beside it.)
- the gcc tree must be called `gcc`, because anonymous-namespace symbols embed the source path.

Header paths in the stabs read `/mingw/include/c++/3.2.3/...` where a native install's read `c:/mingw/include/c++/3.2.3/...`.
msvcrt.dll itself is imported, so the C library proper has no source to describe. `_chkstk` comes from `cygwin.asm` run through
the assembler, which leaves an `SO /tmp/cc….s` with line records. No DWARF; under wine it prints the same line as
`hello_gcc345.exe` and exits 8.

`classes_msvc_clang.exe` is an MSVC-ABI build with virtual inheritance and no CRT: `classes_msvc_rt.cc` stands in for `operator new`/`delete` and `type_info`'s vftable, which the RTTI type descriptors point at. The constructors are `noinline`, so each stores its class's vftables and vbtables into `this`.

`hello_msvc_clang.exe` is `hello.cc` under the MSVC ABI, with no CRT either: `msvc_stub/stdio.h` declares `printf`, and `hello_msvc_rt.cc` stubs it with the rest of what the build references (`memset`, `_purecall`, `_CxxThrowException`, `__CxxFrameHandler3`, `_fltused`, `operator new`/`delete`, `type_info`'s vftable). It links but does not run.
