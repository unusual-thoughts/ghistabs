# Test fixtures

Real binaries carrying real STABS. No toolchain in existence today can regenerate most of
these — GCC 12 deprecated `-gstabs` and GCC 13 removed the emitter outright — so treat them
as archival: rebuild recipes are in `corpus/`, but the compilers themselves have to be
retrieved from distribution archives first.

The directory listing *is* the corpus. Every file here is auto-discovered by
`:generateFixtureTests` (one regression class per fixture × `CONCURRENT`/`AFTER` mode) and by
`IntegrationFixtures.ALL`, so dropping a binary in is enough to put it under test and nothing
can sit here silently untested. Both skip `.md`, which is why this file doesn't become a
fixture named `README.md`.

## The corpus

| Fixture                                        | Format            | Compiler              | Source              | Debug reach | Symbols       |
| ---------------------------------------------- | ----------------- | --------------------- | ------------------- | ----------- | ------------- |
| `xmltest_gcc345.exe`                           | PE32 i386         | MinGW GCC **3.4.5**   | TinyXML 1.x         | own code    | COFF          |
| `xmltest_gcc345_fullstabs.exe`                 | PE32 i386         | MinGW GCC **3.4.5**   | TinyXML 1.x         | + libstdc++ | COFF          |
| `xmltest_gcc421.exe`                           | PE32 i386         | MinGW GCC **4.2.1**   | TinyXML 1.x         | own code    | COFF          |
| `xmltest_gcc421_fullstabs.exe`                 | PE32 i386         | MinGW GCC **4.2.1**   | TinyXML 1.x         | + libstdc++ | COFF          |
| `xmltest_gcc421_stripped.exe`                  | PE32 i386         | MinGW GCC **4.2.1**   | TinyXML 1.x         | own code    | **none**      |
| `xmltest_gcc421_fullstabs_stripped.exe`        | PE32 i386         | MinGW GCC **4.2.1**   | TinyXML 1.x         | + libstdc++ | **none**      |
| `crypto_mi_test_gcc345.exe`                    | PE32 i386         | MinGW GCC **3.4.5**   | Crypto++ 5.6.2      | own code    | COFF          |
| `crypto_mi_test_gcc345_fullstabs.exe`          | PE32 i386         | MinGW GCC **3.4.5**   | Crypto++ 5.6.2      | + libstdc++ | COFF          |
| `crypto_mi_test_gcc421.exe`                    | PE32 i386         | MinGW GCC **4.2.1**   | Crypto++ 5.6.2      | own code    | COFF          |
| `crypto_mi_test_gcc421_fullstabs.exe`          | PE32 i386         | MinGW GCC **4.2.1**   | Crypto++ 5.6.2      | + libstdc++ | COFF          |
| `crypto_mi_test_gcc421_stripped.exe`           | PE32 i386         | MinGW GCC **4.2.1**   | Crypto++ 5.6.2      | own code    | **none**      |
| `crypto_mi_test_gcc421_fullstabs_stripped.exe` | PE32 i386         | MinGW GCC **4.2.1**   | Crypto++ 5.6.2      | + libstdc++ | **none**      |
| `locale_test_gcc345_fullstabs.exe`             | PE32 i386         | MinGW GCC **3.4.5**   | locale-facet driver | + libstdc++ | COFF          |
| `locale_test_customlibstdcxx.exe`              | PE32 i386         | MinGW GCC **4.2.1**   | locale-facet driver | + libstdc++ | COFF          |
| `locale_test_customlibstdcxx_stripped.exe`     | PE32 i386         | MinGW GCC **4.2.1**   | locale-facet driver | + libstdc++ | **none**      |
| `xmltest`                                      | ELF x86-64 PIE    | Debian GCC **12.2.0** | TinyXML **2**       | own code    | ELF `.symtab` |
| `box2d_tests`                                  | ELF x86-64 PIE    | Debian GCC **12.2.0** | Box2D test driver   | own code    | ELF `.symtab` |
| `hello_aout_gcc295.o`                          | a.out OMAGIC i386 | GCC **2.95**          | hand-written C      | own code    | in symtab     |
| `zlib_aout_gcc263.o`                           | a.out OMAGIC i386 | GCC **2.6.3**         | zlib 1.1.4          | own code    | in symtab     |

Spread: **GCC 2.6.3 → 12.2.0**, three container formats, 32- and 64-bit, Windows and Linux.
The PE binaries are all statically linked and console-mode.

Despite the shared name, the ELF `xmltest` is **TinyXML 2** while the `xmltest_*.exe` are
**TinyXML 1.x** — different projects with different APIs, not two builds of one source tree.

## What the axes mean

**`_fullstabs`** — linked against a `libstdc++.a` rebuilt from matching GCC source with
`-gstabs+ -O0`, so the standard library's own internals (locale, iostream, string, EH) carry
STABS. Without it you only get your own code plus whatever templates your code instantiates
from headers: the `libstdc++.a` shipped with the toolchain was released stripped and has *no* debug info
of any kind. The locale-facet drivers exist specifically to exercise this — locale is
non-template stdlib internals, unreachable any other way.

**`_stripped`** — the PE/COFF symbol table removed, `.stab`/`.stabstr` intact. This is a
deliberate probe, not an accident: it forces the importer to work from the debug records
alone, so it can't quietly grow a dependency on the PE symbol table. `objcopy
--remove-section` does *not* do this — the COFF symbol table is referenced by a header
pointer, not stored as a section.

**Container** — PE keeps stabs in `.stab`/`.stabstr` sections; a.out has no debug sections at
all and interleaves stab records with link-time symbols in the single symbol table,
distinguished by the `N_STAB` mask. ELF is the same section layout as PE, and is here mainly
because `x86-64` and PIE exercise different address/storage paths.

## Gotchas worth knowing before you regenerate anything

- **GCC 4.2.1's CRT startup objects inject DWARF** regardless of `-gstabs`, because they ship
  prebuilt. Every 4.2.1 binary needs the `.debug_*` sections stripped post-link or it carries
  both formats. GCC 3.4.5's CRT objects do *not* do this — those come out STABS-only.
- **The two a.out fixtures cannot be rebuilt on a modern kernel at all.** libc5's `sbrk` needs
  `brk()` to return the exact unaligned address requested, which Linux has page-aligned for
  years, so the compilers die with "virtual memory exhausted". They were built under
  `qemu-system-i386` on a 2.4.18 kernel. `qemu-user` does not help.
- **GCC 2.6.3 C++ is not supported by the parser** — pre-2.8.0 stabs grammar (bare integer
  type ids, `Tt` on explicit typedefs, `##` method forms). Its C output parses cleanly, which
  is why the a.out fixtures are C.

## Adding your own

Drop a binary in and it is under test on the next run — no registration step. It needs a
committed baseline before `countersWithinBaseline` means anything; generate the first one with
`./gradlew integrationTest -PregenerateBaselines=true` and commit the resulting JSON, whose diff
is then the record of exactly which counters move on later changes.

Not every fixture has to be committed. Anything absent is skipped cleanly by the tests rather
than failing them, so binaries that cannot be redistributed can sit here locally and stay out of
git. The fixtures committed here are built from open-source projects (TinyXML, Crypto++, zlib,
Box2D).
