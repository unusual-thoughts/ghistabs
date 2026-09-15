# Test fixtures

Real binaries carrying real STABS. No toolchain in existence today can regenerate most of
these — GCC 12 deprecated `-gstabs` and GCC 13 removed the emitter outright — so treat them
as archival: rebuild recipes are in `corpus/`, but the compilers themselves have to be
retrieved from distribution archives first.

The directory listing *is* the corpus. Every file here is auto-discovered by
`:generateFixtureTests` (one regression class per fixture × `CONCURRENT`/`AFTER` mode) and by
`Fixtures.ALL`, so dropping a binary in is enough to put it under test and nothing
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
| `hello_aout_gcc295.o`                          | a.out OMAGIC i386 | GCC **2.95.2**        | hand-written C      | own code    | in symtab     |
| `tinyxml_aout_gcc295.o`                        | a.out OMAGIC i386 | GCC **2.95.2**        | TinyXML 1.x (C++)   | own code    | in symtab     |
| `zlib_aout_gcc263.o`                           | a.out OMAGIC i386 | GCC **2.6.3**         | zlib 1.1.4          | own code    | in symtab     |
| `tinyxml_aout_gcc258.o`                        | a.out OMAGIC i386 | GCC **2.5.8**         | TinyXML 1.x †       | own code    | in symtab     |
| `tinyxml_aout_gcc263.o`                        | a.out OMAGIC i386 | GCC **2.6.3**         | TinyXML 1.x (C++)   | own code    | in symtab     |
| `xmltest_aout_gcc263`                          | a.out QMAGIC i386 | GCC **2.6.3**         | TinyXML 1.x, linked | own code    | in symtab     |
| `iostream_test_aout_gcc263.o`                  | a.out OMAGIC i386 | GCC **2.6.3**         | libg++ MI driver    | own code    | in symtab     |
| `iostream_test_aout_gcc263_fullstabs`          | a.out QMAGIC i386 | GCC **2.6.3**         | libg++ MI driver    | + libg++    | in symtab     |
| `xmltest_elf_gcc272`                           | ELF i386 static   | GCC **2.7.2.3**       | TinyXML 1.x, linked | own code    | ELF `.symtab` |

Spread: **GCC 2.5.8 → 12.2.0**, three container formats, 32- and 64-bit, Windows and Linux.
The PE binaries are all statically linked and console-mode.

Six fixtures, one per configuration worth distinguishing, chosen by measuring what each actually
contains rather than by which toolchains happened to build. `other/` holds seven more that were
built and then set aside as measurably redundant — Crypto++ 1.0 at all three compilers (its
`cryptlib.cc` yields five plain single-inheritance classes and, despite the library's reputation,
**no** multiple inheritance), a second zlib, and per-compiler repeats of TinyXML and the driver.
They are there rather than deleted so a call can be revisited; discovery is `listFiles()` filtered
to `isFile`, so a subdirectory is never picked up.

What each one is here for:

| Fixture                               | The only one that has …                                            |
| ------------------------------------- | ------------------------------------------------------------------ |
| `iostream_test_aout_gcc263_fullstabs` | virtual bases, multiple inheritance, private inheritance — 4/7/1    |
| `xmltest_aout_gcc263`                 | a.out **linked** C++: 41 classes over 17 CUs, vtables at real addresses |
| `xmltest_elf_gcc272`                  | **ELF** at a pre-2.8 dialect — container isolated from dialect      |
| `tinyxml_aout_gcc258.o`               | the **oldest** compiler, with vtables, and the 2.5.8-only encodings |
| `tinyxml_aout_gcc263.o`               | an unlinked object of the same source as `xmltest_aout_gcc263`, stock |
| `iostream_test_aout_gcc263.o`         | the own-code half of the `_fullstabs` pair: bases as `xs` cross-refs |

**†** — `tinyxml_aout_gcc258.o` is **not stock TinyXML**. GCC 2.5.8 predates both `bool` (2.6)
and the new-style casts (2.7), so the source is mechanically de-modernised: `bool`/`true`/`false`
come from `-Dbool=int -Dtrue=1 -Dfalse=0`, and `static_cast`/`const_cast`/`reinterpret_cast` are
rewritten to C-style by one `sed` (the only other pre-standard constructs, `explicit` and the
`template` member, are already behind TinyXML's own `TIXML_EXPLICIT` / `TIXML_USE_STL` macros).
Nothing is hand-edited and the transformation is in `corpus/gcc263_aout/`. `tinyxml_aout_gcc263.o`
is the stock control: same source, same ten classes, so the rewrite itself can be diffed.

**2.5.8 is a slightly different dialect, which is why it is kept**: it references an existing type
id where 2.6.3 defines the pointer inline (`#21,15,20,1,15;` vs `#21,16,25=*21,1,16;`), and its
builtin numbering is shifted by one because 2.6.3 has `bool` at `t15`, pushing `void` to `t16`.

Despite the shared name, the ELF `xmltest` is **TinyXML 2** while the `xmltest_*.exe` are
**TinyXML 1.x** — different projects with different APIs, not two builds of one source tree.

## What the axes mean

**`_fullstabs`** — linked against a `libstdc++.a` rebuilt from matching GCC source with
`-gstabs+ -O0`, so the standard library's own internals (locale, iostream, string, EH) carry
STABS. Without it, you only get your own code plus whatever templates your code instantiates
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

## The pre-2.8 axis

`gcc258`, `gcc263` and `gcc272` are a different **C++ ABI**, not just an older dialect, and the
stabs say which one they are. `__vtbl_ptr_type` is the discriminator:

| Compiler                  | `__vtbl_ptr_type`                           | Vtable layout                 |
| ------------------------- | ------------------------------------------- | ----------------------------- |
| 2.5.8 / 2.6.3 / 2.7.2.3   | `T18=s8__delta:…;__index:…;__pfn:19=*16,…`  | 8-byte records, **pfn at +4** |
| 2.95 and later            | `t(0,22)=*(0,23)=f(0,1)`                    | plain function pointers       |

`Gcc2Abi` models only the later shape (`stride = ptrSize`, `pfnOffset = 0`), which is why the
pre-2.8 fixtures fail `vftablesAreShiftSCompatible` with "N of N vftables are mostly untyped
slots". `headerBytes = 2 * ptrSize` is right for both, though for different reasons — pre-2.8
the leading 8 bytes are an entry *count*, not RTTI (`flag_rtti` is 0 until 2.8.0).

These also carry **bare type ids** (`t1`, `T18`) rather than `(file,type)` pairs, on ELF as much
as on a.out: `DBX_USE_BINCL` only arrives in 2.8.0. `xmltest_elf_gcc272` therefore isolates
"same pre-2.8 dialect, different container" against `xmltest_aout_gcc263`.

On a.out the `CPLUS_MARKER` is `$` — vtables are `__vt$9TiXmlNode` and statics
`_11TiXmlString$npos`, where the 2.95 ELF fixtures spell both with `_`.

Pre-2.8 language limits decide what each compiler could build at all: `bool` arrives in **2.6**
(so 2.5.8 cannot compile TinyXML) and exception handling in **2.7** (so 2.6.3 manages 40/50 of
Crypto++ 1.0 against 2.7.2.3's 46/50, the gap being `sorry, not implemented: exception
handling not supported`).

### What the rest of the corpus does at this vintage

Measured, so nobody repeats it:

| Corpus              | 2.5.8      | 2.6.3      | blocker                                     |
| ------------------- | ---------- | ---------- | ------------------------------------------- |
| zlib 1.1.4          | **17/17**  | **17/17**  | —                                           |
| Crypto++ 1.0        | 33/50      | 40/50      | `bool`, then exception handling             |
| TinyXML 1.x         | **4/4** †  | **6/6**    | `bool` + casts, via the † shim above        |
| libg++ MI driver    | **1/1**    | **1/1**    | needs period libg++ at 2.5.8, see below     |
| Box2D v3 (C)        | 0/38       | 0/38       | `stdint.h` — C99                            |
| TinyXML2            | 0/1        | 0/1        | `stdint.h` — C99                            |
| Crypto++ 5.6.2      | 2/134      | 2/134      | `<memory>`, `<typeinfo>`, `<algorithm>`     |

So the pre-2.8 rungs top out at zlib, Crypto++ 1.0 and TinyXML 1.x; everything C99 or C++98 is
permanently out of reach and not worth re-attempting.

**At 2.5.8 the header set matters more than the compiler, and C and C++ want different ones.**

- **C** (zlib) needs **buzz's libc4** headers. Slackware 1.1.2's `include.tgz` references
  `linux/errno.h`, `linux/limits.h` and `linux/types.h`, which exist only as a symlink into a
  kernel source tree the package does not ship — zlib goes 4/17 → **17/17** on that change alone.
  (Slackware's own `d4/kernel.tgz` would supply them, but the copy on both ibiblio and
  mirrors.slackware.com is CRC-corrupt.)
- **C++** (TinyXML, the MI driver) needs **Slackware's** headers first: 2.5.8's C++ frontend
  cannot parse buzz's libc4 `stdlib.h:301` (`parse error before 'const'`), and libgxx's
  `streambuf.h` needs *its own* `_G_config.h` or it fails with `invalid use of undefined type
  '_IO_FILE_plus'`. Put libc4 second purely as a fallback for the missing `linux/*` and `asm/*`.
- The MI driver additionally needs **Slackware's `d6/libgxx.tgz`** (period libg++), not libg++
  2.6.2 — 2.6.2's own `iostream.h:91` uses `bool`. The period one is bool-free and has the same
  virtual diamond (`iostream : public istream, public ostream` over `virtual public ios`).
- Link with `-B<libdir>/`, not just `-L`: the driver resolves `crt0.o` through startfile
  prefixes, so `-L` alone yields `ld: cannot open crt0.o`.

The 2.5.8 build of the MI driver is in `other/` rather than shipped: it compiles and links but
segfaults at startup (libg++ 2.5 static-init), and its records are the same shape as the 2.6.3
one's, which is kept. The 2.6.3 `_fullstabs` binary is where the linked-MI coverage actually
comes from.

## Gotchas worth knowing before you regenerate anything

- **GCC 4.2.1's CRT startup objects inject DWARF** regardless of `-gstabs`, because they ship
  prebuilt. Every 4.2.1 binary needs the `.debug_*` sections stripped post-link, or it carries
  both formats. GCC 3.4.5's CRT objects do *not* do this — those come out STABS-only.
- **The a.out fixtures need two different recipes.** The gcc 2.6.3 one runs the compiler natively
  under `qemu-system-i386` on a 2.4.18 kernel, because libc5's `sbrk` needs `brk()` to return the
  exact unaligned address requested and Linux has page-aligned it for years — the compiler dies
  with "virtual memory exhausted" otherwise, and `qemu-user` does not help. The gcc 2.95.2 ones
  need no VM: Debian potato's `cc1`/`cc1plus` still run on a modern host, and only the *assembler*
  has to be period-correct.
- **Use an a.out assembler no older than binutils 2.28 or so** *when assembling gcc 2.95 output*.
  binutils 2.7's `as` ORs `0x02` into `n_type` on forward-referencing `.stabn`, turning `N_RBRAC`
  (0xE0) into `N_BCOMM` (0xE2) and `N_LBRAC` into `N_EXCL`; the records are then silently dropped.
  Build binutils **2.30** `--target=i386-linuxaout --enable-obsolete` instead (2.31 removed a.out
  support, and 2.30 will not configure it without the flag). Balanced `N_LBRAC`/`N_RBRAC` counts
  are the check. This does **not** apply to the gcc 2.5.8/2.6.3 route: buzz's `as` is binutils
  **2.5.2**, which predates the bug and comes out balanced (265/265 on `tinyxml_aout_gcc263.o`,
  650/650 on the linked iostream binary), so no host binutils build is needed there.
- **`-gstabs+`, not `-gstabs`, on the pre-2.8 compilers.** Plain `-gstabs` emits **zero** `!`
  inheritance specs — 10 vs 0 on tinyxml.cpp with everything else identical, because inheritance
  is gated on `use_gnu_debug_info_extensions`.
- **gcc 2.5.8 does not know the `.cpp` suffix.** It treats such a file as a linker input, warns,
  and exits **0**, so a build loop keyed on the exit status reports success having compiled
  nothing. Copy to `.cc` first.
- **Crypto++ 1.0 ships as a DOS zip** — CRLF plus a trailing `^Z`. Left alone the errors read
  like language failures (`parse error before '=='`, `parse error before character 032`).
  `sed -i 's/\r$//; s/\x1a//g'` took 2.7.2.3 from 26/50 files to 46/50.
- **Today's `as` defaults to x86-64**, so 1997 i386 output fails with "invalid instruction suffix
  for `push'" until given `-Wa,--32`; linking likewise needs `ld -m elf_i386`. This is what makes
  the gcc 2.7.2.3 ELF fixtures buildable on a modern host with no VM at all — only the *headers*
  (Debian slink `libc6-dev` 2.0.7 + `libg++272-dev`) have to be period-correct, since modern
  glibc headers will not parse under that compiler.
- **gcc 2.95 targets ELF, so its assembly needs two rewrites** before an a.out assembler accepts
  it: `.section .gnu.linkonce.*` has no a.out equivalent and must be folded into `.text`/`.data`
  (`-fno-weak` does not suppress it for COMDAT inline members), and `.align` means a *byte count*
  on ELF but a *power of two* on a.out, so `.align 32` must become `.align 5` — otherwise gas dies
  with an internal error in `size_seg`. The resulting object carries `(file,type)` type ids and
  `N_BINCL`, since the ELF target defines `DBX_USE_BINCL` — a combination no historical a.out
  toolchain produced.
- **Pre-3.0 C++ uses *minimal debug***, which is what `tinyxml_aout_gcc295.o` pins down: a method
  reads `##<returntype>` with its argument types in the mangled name instead. There is no flag to
  turn it off — `flag_minimal_debug` is compile-time, keyed on whether the target permits `$` and
  `.` in labels. 2.5.8/2.6.3/2.7.2.3 additionally emit bare integer type ids and `Tt` on explicit
  typedefs. All of this *is* recovered; what these fixtures actually break is the vtable ABI (see
  "The pre-2.8 axis"), not the dialect.

## Adding your own

Drop a binary in, and it is under test on the next run — no registration step. It needs a
committed baseline before `countersWithinBaseline` means anything; generate the first one with
`./gradlew integrationTest -PregenerateBaselines=true` and commit the resulting JSON, whose diff
is then the record of exactly which counters move on later changes.

Not every fixture has to be committed. Anything absent is skipped cleanly by the tests rather
than failing them, so binaries that cannot be redistributed can sit here locally and stay out of
git. The fixtures committed here are built from open-source projects (TinyXML, Crypto++, zlib,
Box2D).
