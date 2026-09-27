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
| `hello_elf_gcc33`, `_gcc34` | gcc 3.3.5 / 3.4.4, i386 | `docker run --platform linux/386 debian/eol:sarge` (`g++`, `g++-3.4`) | — |
| `hello_elf_gcc41` … `_gcc8` | gcc 4.1.2 / 4.3.2 / 4.4.5 / 4.7.2 / 4.9.2 / 6.3.0 / 8.3.0, i386 | `debian/eol:` etch / lenny / squeeze / wheezy / jessie / stretch / buster | — |
| `hello_elf_gcc10`, `_gcc12` | gcc 10.2.1 / 12.2.0, i386 PIE | `debian/eol:bullseye` (security via its snapshot.debian.org line), `debian:bookworm` | — |
| `hello_gcc345.exe`, `hello_gcc421.exe` | MinGW gcc 3.4.5 / 4.2.1, PE32 | `debian/eol:etch` / `lenny`, package `mingw32`, `-static`; 4.2.1 then `objcopy --remove-section='.debug_*'` | — |

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
static/const/virtual/pure members, single + multiple + virtual inheritance, templates with nested types,
by-value struct return, varargs, register/static locals, nested scopes and a throw/catch. Every build prints
the same line and exits 8. The try/catch lives in its own function because gcc 2.7.2.3 ICEs
(`unrecognizable insn`) on EH inside `main` next to a `register` local.
