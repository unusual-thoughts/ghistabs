# ghidra-stabs

A Ghidra extension that imports [**STABS**](https://sourceware.org/gdb/onlinedocs/stabs.pdf) debug
info (`.stab` / `.stabstr`) into a program: data types, function signatures, parameters and locals,
C++ classes and vtables, constants and static members. On top of the import it can reconstruct, per
source file, a line-aligned **source skeleton** or an annotated **decompilation**.

STABS — also called **DBX**, after the original BSD debugger it was written for — is an ancient
text-based predecessor to DWARF, named for the *symbol table strings* it hides the debug info in.

It was the default debug symbol format `-g` gave you on the prehistoric a.out binary format,
as well as ELF targets until they moved to DWARF-2 in gcc **3.1** (2002), while the Windows targets —
Cygwin and MinGW alike, which share one gcc configuration — kept it until **4.3.0** (2008). So
stabs found in the wild are often old MinGW .exe's.

Ghidra has no built-in stabs importer — the records in the stab sections are not parsed. This fills
that gap.

## Supported configurations

|                       | Supported                                                                                                                                                                                             |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Ghidra**            | **12.x**                                                                                                                                                                                              |
| **Binary containers** | **PE/COFF**, **ELF** and **a.out** (OMAGIC)                                                                                                                                                           |
| **Instruction sets**  | `i386` / `x86-64`                                                                                                                                                                                     |
| **Compiler**          | **gcc**, on both Unix and Cygwin/MinGW targets, up to gcc **12** (`-gstabs` was deprecated in 12 and removed outright in 13). Stabs produced by other compilers are out of scope but may mostly work. |
| **Languages**         | **C** from at least gcc **2.6.3** <br> **C++** from gcc **3.2**                                                                                                                                       |
| **Formats**           | `-gstabs` and `-gstabs+` alike                                                                                                                                                                        |
| **Also**              | object files and linked images alike, and images whose  symbol table has been stripped, provided the stabs themselves survive.                                                                        |

## What it gives you

- **The full type graph.** Structs, unions, enums, typedefs, pointers, references, arrays and
  function pointers, deduplicated across the whole program. Types are categorized by source file
  (with common parent directory stripped), and by C++ namespace, with standard library types under `/std/…`
- **Real function signatures.** Return types and full parameters, applied to every function
  the compiler described
- **Named, typed locals and parameters.** Parameters and locals alike — stack slots and register
  variables — recover their source names and types, replacing default decompiler names like
  `local_1c` or `uVar3`.
- **Proper C++ classes.** Class namespaces with their methods inside them, taking a properly typed `this`.
  Class structures contain their base classes and vtable pointers at their true offsets.
  vtables are built and applied at their symbol location, and vtable struct types with full
  method signatures.
- **Data laid out and named.** Globals and statics defined at their addresses with their real
  types; C strings defined where pointers lead; static class members reconnected to the symbols
  they were emitted as.
- **Constants.** Compile-time constants become equates, so a bare `0x1F4`
  in the listing can be displayed as `Timeout::DEFAULT_MS`, and are additionally collected into
  enum datatypes (grouped by namespace and width) you can apply to fields and parameters.
- **Source map.** Lexical scopes are annotated, and line number mappings are imported into Ghidra.
  Source file to header import transforms too.

On a C++ binary the mangled symbols already carry a lot on their own: `_ZN3app4Conn4sendEPKcj`
demangles to `app::Conn::send(char const*, unsigned int)` — namespace, class, method and parameter
types, with no debug info at all. What the mangling never encodes is the return type, parameter
names, the type of a data symbol, and anything about layout: field names and offsets, enum values,
typedefs, and which methods are virtual and in what slot order. That is the gap this fills, and
Ghidra's own demangler output is reconciled against the imported types, so its synthesized
placeholder structs are replaced by the real definitions rather than competing with them.

## Install

Grab the zip matching your Ghidra version from `dist/`, then either

- **Ghidra GUI:** `File > Install Extensions… > +`, pick the zip, restart Ghidra; or
- **Gradle:** `./gradlew installExtension` (builds and unpacks straight into your Ghidra user
  extensions dir, e.g. `~/.config/ghidra/ghidra_12.1.2_DEV/Extensions`; set `GHIDRA_USER_DIR`
  to override), then restart Ghidra.

## Building

Requires Ghidra 12.x and a JDK 21 toolchain. An extension zip only loads into the Ghidra
release it was built against.

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra   # or pass -PGHIDRA_INSTALL_DIR=...
./gradlew buildExtension                # zip under dist/
./gradlew installExtension              # build + install into the Ghidra user dir
./gradlew buildCli                      # standalone headless CLI at build/cli/ghidra-stabs
./gradlew test                          # unit tests (see TESTING.md for the other tiers)
```

## Using it in Ghidra

### The Stabs Importer analyzer

Runs automatically during auto-analysis on any program that has both a `.stab` and a
`.stabstr` memory block, at `LOW_PRIORITY` — after Ghidra's demangler, whose output it builds
on. It imports **once per program**: a `Stabs Imported` flag is stored in the program info, so
re-analysis won't redo the work. Also available as one-time analysis
(`Analysis > One Shot`).

Options (`Analysis > Auto Analyze… > Stabs Importer`):

| Option                                   | Default | Effect                                                                                                                                                                        |
| ---------------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Reconstruct C++ classes**              | on      | Class namespaces, this-typed member methods, `<Class>_vftable` structs at `_ZTV`. Off leaves plain structs — member calls lose `this`/args and virtual calls stay unresolved. |
| **Apply scope plate comments**           | on      | Plate comments at lexical scopes where `N_LBRAC`/`N_RBRAC` info exists.                                                                                                       |
| **Shorten templated names via typedefs** | off     | Rename long templated types onto their shorter aliases (`basic_string<char, …>` → `string`), recursively inside other templates.                                              |
| **Fold source-file spellings**           | on      | Collapse gcc's two spellings of one physical header (full include path vs bare `#include "x.h"`) onto one rendered output file, by unique basename.                           |
| **Overlay `.stab` section structs**      | on      | Decode every `.stab` entry into a `StabRecord` struct with references into `.stabstr` and back to the code/data it describes.                                                 |
| **Minimum log level**                    | `INFO`  | Floor for diagnostics written to the analysis log. Bookmarks and counters are emitted regardless.                                                                             |
| **Source roots**                         | none    | `;`-separated local checkouts of the sources this binary was built from; each recorded source directory found under a root becomes a directory transform, so paths resolve to real files. The **Browse** button picks directories only, multi-selects, and appends to the list. Read at import time — adding a root later needs a re-import. |

Diagnostics land in three places: the analysis **MessageLog** (filtered by the log level),
an **`Analysis` bookmark** at every addressed diagnostic, and a summary of counters at the
end of the import.

### `Tools > Stabs`

- **Re-import** — clears the `Stabs Imported` flag and re-runs auto-analysis, so the importer
  runs again over the current program. Use it after changing analyzer options. Enabled only
  when the program actually has `.stab`/`.stabstr` blocks.

### `File > Export Program…`

Two formats write the reconstructed sources, one file per source file — the headless driver's
two modes, picked in the format list (Ghidra fixes an exporter's extension at construction, so
they're two exporters rather than one with a mode option):

- **Stabs Decompilation** (`.decomp`) — code at the original source lines, gcc SjLj exception
  scaffolding elided.
- **Stabs Source Skeleton** (`.skeleton`) — every declaration at its original line, no code.

The export dialog takes a *file* path and its browse button offers files only, so the first
option is an **Output directory** — a directories-only chooser, and where the render lands when
set; left empty, the dialog's path is used as the directory (hence the appended extension). The
rest are render flags: *Elide gcc SjLj exception scaffolding* (decompilation only), *Annotate
locals with their storage*, *Render source line n at output line n*. Requires the importer to
have run first.

### Supporting analyzers

Independent of stabs, enabled by default, each re-runnable and available as one-shot analysis:

- **Struct-return ABI (x86 gcc)** — x86:LE:32 gcc only. gcc/MinGW returns a class in memory
  through a hidden caller-allocated pointer whenever it is non-trivial for calls, *regardless
  of size*, while trivial small aggregates really do come back in `EAX`/`EDX:EAX`. No cspec
  rule can express that, so `x86gcc.cspec` is wrong in both directions at once. This analyzer
  reads the callee's stack purge (which settles the question: `RET 0x4` vs bare `RET`) and,
  where it disagrees with the cspec, reassigns the function to a derived calling convention
  (`__thiscall_memret`, `__cdecl_regret`, …) installed as a program spec extension.
- **In-Function Gap Disassembler** — disassembles undefined bytes that lie *inside* a
  function's extent: hot/cold split holes and exception landing pads reachable only by
  unwinding. Only runs where every byte of the gap decodes cleanly.
- **Filler Byte Condenser** — collapses GAS `.p2align` padding in code (NOP idioms and the
  jump-over-fill form) into `Alignment` data, so it isn't mistaken for undescribed data.

The last two run before the importer, mostly so its data-coverage report doesn't flag
compiler scaffolding as missing.

## Headless CLI

`./gradlew buildCli` emits a self-contained launcher at `build/cli/ghidra-stabs` that boots
Ghidra, loads a binary, runs full auto-analysis plus the stabs import, and renders every
source file — no GUI, no Ghidra project. (`./gradlew runCli -Pargs="…"` runs the same entry
point in-process.)

```bash
build/cli/ghidra-stabs skeleton myprogram.exe -d out/skeletons
build/cli/ghidra-stabs decomp   myprogram.exe -d out/decomps --shorten-typedefs
```

The two modes are not the same output with decompilation bolted on — they answer different
questions.

- **`skeleton`** is the *diagnostic* view: everything the debug info places in that file, at its
  original line — typedefs, type bodies, globals, function signatures, every parameter and
  local, plus `// L n @ 0xADDR` address annotations. Nothing is dropped, so misattributions stay
  visible: a declaration gcc's `N_SOL` records filed under the wrong source file is kept and
  tagged `stale N_SOL?` rather than quietly removed. Anonymous aggregates, which have no source
  line to sit on, are appended as a trailing block. Output stays fully source-aligned.

- **`decomp`** is the *readable* view, and declarations give way to code. Within each function's
  line span, Ghidra's decompiled statements are laid out K&R-indented, each tagged `// ⇐ L NN`
  with the source line its instructions came from — and everything the decompilation already
  shows is cleared out: address annotations, brace delimiters and local declarations are
  dropped outright, stale fragments sharing a line with real content are purged, and anything
  else stranded on those lines (a type gcc mis-filed here) is demoted to a `// stray:` comment
  carrying its original line's provenance, never code. Real file-scope globals keep their line.
  `#include` lines are reconstructed and trailing blank lines trimmed. `--elide-sjlj` (default)
  additionally strips gcc's SjLj exception scaffolding; `--no-elide-sjlj` keeps it. Both are
  no-ops on DWARF-EH (ELF) binaries.

So a line that carried three speculative declarations in the skeleton typically carries one
statement of decompilation in `decomp`, with the rest either gone or demoted to comments. Read
the skeleton when you want to see what the stabs *claimed*; read `decomp` when you want the
code.

Shared options:

| Option                                                | Default  | Effect                                                                                                                               |
| ----------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `-d`, `--target-dir`                                  | required | Output directory; one file per source, named from the source path.                                                                   |
| `--classes` / `--no-classes`                          | on       | Same as the analyzer's class reconstruction.                                                                                         |
| `--shorten-typedefs`                                  | off      | Same as the analyzer's typedef shortening.                                                                                           |
| `--fold-sources` / `--no-fold-sources`                | on       | Same as the analyzer's source folding.                                                                                               |
| `-v`, `--log-level`                                   | `INFO`   | `DEBUG`/`INFO`/`WARN`/`ERROR`; the log streams live to stderr.                                                                       |
| `--log FILE`                                          | stderr   | Redirect the import log to a file.                                                                                                   |
| `--disable-analyzer NAME`                             | —        | Turn off every analyzer whose name contains `NAME` (repeatable). Render the same binary with and without one to A/B what it changes. |
| `--records-json`, `--harvest-json`, `--registry-json` | —        | Dump the parsed stab records / harvest / materialized type registry as JSON.                                                         |
| `--degradation-log FILE`                              | —        | Grouped report of every type that materialized to something weaker than the stabs described.                                         |

## Status

The importer is the mature part; skeleton and especially decompilation rendering are usable
but still under active work.

## Bibliography
### Stabs format
There is no standard — stabs is a semi-documented convention, and the two manuals disagree with each other and with what gcc emits.

- *STABS Debug Format*, Menapace, Kingdon & MacKenzie (Free Software Foundation) — the GNU
  reference, distributed with gdb.
  [HTML](https://sourceware.org/gdb/onlinedocs/stabs.html/) ·
  [PDF](https://sourceware.org/gdb/onlinedocs/stabs.pdf)
- *Stabs Interface*, Sun Microsystems (Sun Studio 11) —
  [PDF](https://web.archive.org/web/20061115071332/http://dsc.sun.com/sunstudio/documentation/ss11/stabs.pdf). Describes constructs
  gcc never emits, and omits GNU extensions gcc emits constantly.
- [Stabs](https://en.wikipedia.org/wiki/Stabs) on Wikipedia

### Implementations**
Settles what a real binary actually contains when the manuals disagree.

- [`gcc/dbxout.c`](https://gcc.gnu.org/git/?p=gcc.git;a=history;f=gcc/dbxout.c;hb=refs/tags/releases/gcc-12.3.0)
  — the emitter. Deleted in gcc 13
- [`gdb/stabsread.c`](https://sourceware.org/git/?p=binutils-gdb.git;a=history;f=gdb/stabsread.c;hb=refs/tags/gdb-12.1-release)
  — the reader. Also since removed from gdb.
- [`include/aout/stab.def`](https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=include/aout/stab.def)
  — the record-type table, still in binutils.
- [gcc 3.1 release notes](https://gcc.gnu.org/gcc-3.1/changes.html) — "The default debugging
  format for most ELF platforms … has changed from stabs to DWARF2."

### Prior art
- [RidgeX/ghidra-gcc2-stabs](https://github.com/RidgeX/ghidra-gcc2-stabs) — a Ghidra script
  parsing GCC 2.x stabs.
- [chaoticgd/ccc](https://github.com/chaoticgd/ccc) — library and tools for debugging symbols in
  PS2 games, focused on STABS in `.mdebug` sections.
- [uyjulian/stab_debuginfo_utils](https://github.com/uyjulian/stab_debuginfo_utils) — STAB
  debug information utilities, for x86 and r3000 MIPS.
