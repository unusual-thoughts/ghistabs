# Feature fixtures

Small single-purpose binaries, kept out of the fixture matrix (which only scans the parent directory)
and exercised by their own integration test.

| Fixture | Compiler | Built in | Test |
|---|---|---|---|
| `ptrmem_elf_gcc295` | gcc 2.95.2, i386 | Debian potato (`~/machines/potato`, systemd-nspawn) | `MemberPointerIntegrationTest` |
| `ptrmem_elf64_gcc12` | gcc 12.2.0, x86-64 | `docker run debian:bookworm` + `apt-get install g++` | `MemberPointerIntegrationTest` |
| `reloc_elf_gcc295.o` | gcc 2.95.2, i386 | Debian potato (`~/machines/potato`, systemd-nspawn) | `RelocatableObjectIntegrationTest` |
| `reloc_elf64_gcc12.o` | gcc 12.2.0, x86-64 | `docker run debian:bookworm` + `apt-get install g++` | `RelocatableObjectIntegrationTest` |

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
