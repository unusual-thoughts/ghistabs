# ghidra-stabs

A Ghidra extension that imports [**STABS**](https://sourceware.org/gdb/onlinedocs/stabs.pdf) debug
info (`.stab` / `.stabstr`) into a program: data types, function signatures, parameters and locals,
C++ classes and vtables, constants and static members. On top of the import it can reconstruct, per
source file, a line-aligned **source skeleton** or an annotated **decompilation**.

STABS — also called **DBX**, after the original BSD debugger it was written for — is an ancient
text-based predecessor to DWARF, named for the *symbol table strings* it hides the debug info in.

It was the default debug symbol format `-g` gave you on the prehistoric a.out binary format,
and on ELF targets until they moved to DWARF-2 in gcc **3.1** (2002), while the Windows targets —
Cygwin and MinGW alike, which share one gcc configuration — kept it until **4.3.0** (2008). So
stabs found in the wild are often old MinGW .exe's.

Ghidra has no built-in stabs importer — the records sit in the program as opaque data. This fills
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

- **Real function signatures.** Return types and full parameter lists, applied to every function
  the compiler described — including functions Ghidra's analysis missed entirely, which are
  created from the debug info rather than left as undefined bytes.
- **Names as the compiler recorded them.** Functions take the name from the debug info rather
  than whatever the symbol table happens to carry, so file-local statics get their real names
  instead of `FUN_00401000`, and mangled C++ names resolve to `Class::method`.
- **Named, typed locals and parameters.** Parameters and locals alike — stack slots and register
  variables — recover their source names and types, replacing default decompiler names like
  `local_1c` and `uVar3`.
- **The real type graph.** Structs, unions, enums, typedefs, pointers, references, arrays and
  function pointers, deduplicated across the whole program — one `std::string`, not one per
  compilation unit that happened to mention it.
- **C++ structure that Ghidra can act on.** Classes become real namespaces with their methods
  inside them, taking a properly typed `this`. Base classes are embedded at their true offsets,
  vtables are built and applied at their symbols, and virtual call sites resolve to named
  methods instead of dead-ending in an indirect jump.
- **Data laid out and named.** Globals and statics defined at their addresses with their real
  types; C strings defined where pointers lead; static class members reconnected to the symbols
  they were emitted as.
- **Constants you can actually use.** Compile-time constants become equates, so a bare `0x1F4`
  in the listing can be displayed as `Timeout::DEFAULT_MS`, and are additionally collected into
  enum datatypes (grouped by namespace and width) you can apply to fields and parameters.
- **Types filed where you'd look for them.** Everything lands in a browsable tree that mirrors
  the program's own layout instead of one flat pile: a class from `net/socket.h` under
  `/net/socket.h`, standard-library types under `/std/…`, and C++ namespaces as categories, so
  `std::string` sits at `/std`. Path boilerplate common to every source file is stripped, so the
  tree starts somewhere meaningful rather than at `/home/someone/build/…`.
- **Source-level orientation.** Lexical scopes are annotated, and the line map ties every
  instruction back to the source line it came from — which is what the skeleton and
  decompilation renders are built on.

On a C++ binary the mangled symbols already carry a lot on their own: `_ZN3app4Conn4sendEPKcj`
demangles to `app::Conn::send(char const*, unsigned int)` — namespace, class, method and parameter
types, with no debug info at all. What the mangling never encodes is the return type, parameter
names, the type of a data symbol, and anything about layout: field names and offsets, enum values,
typedefs, and which methods are virtual and in what slot order. That is the gap this fills, and
Ghidra's own demangler output is reconciled against the imported types, so its synthesised
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

### `File > Export Program… > Stabs Decompilation`

Writes the reconstructed render, one file per source file, with gcc SjLj exception scaffolding
elided. The dialog only takes a file path, so the path chosen *is* the output directory (hence
the `.src` extension it appends). Options: *Skeleton only*, *Elide gcc SjLj exception
scaffolding*, *Annotate locals with their storage*, *Render source line n at output line n* —
the render flags the headless driver exposes. Requires the importer to have run first.

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

## Development

`CLAUDE.md` (repo orientation and conventions) and `TESTING.md` (test tiers and flags).

---

## Technical notes: what's parsed, and how

This section is about the format rather than the tool. The reference sources are Sun's *Stabs
Interface* manual, gdb's `stabsread.c`, and gcc's `dbxout.c` — the last being the one that
actually decides what a gcc binary contains.

**Records consumed.** `N_FUN` (function, with its signature), `N_PSYM`/`N_RSYM` (stack and
register parameters), `N_LSYM` (locals and type definitions), `N_GSYM`/`N_STSYM`/`N_LCSYM`
(globals and statics), `N_LBRAC`/`N_RBRAC` (lexical scopes), `N_SO`/`N_SOL`/`N_SLINE` (the source
and line map), `N_BINCL`/`N_EINCL`/`N_EXCL` (include bracketing). `\`-continuation chains are merged
before parsing, and each compilation unit's `.stabstr` offsets are resolved during the read.

**Independent of the symbol table.** Names, types and addresses all come from the stabs, so an
image whose symbol table has been removed but whose `.stab`/`.stabstr` sections survive still
imports in full.

**a.out.** The format stabs originated in has no debug *sections* — its records are entries in the
linker symbol table, identified by the `N_STAB` mask (0340) and interleaved with the link-time
symbols, all sharing one flat string table. Ghidra's a.out loader discards the records themselves, but exposes
the two tables as `.symtab`/`.strtab` blocks, which is what the importer reads. Two things follow
from the flat string table: `n_strx` is an absolute offset, with no `N_UNDF` header rebasing it
per compilation unit, and the link-time symbols sharing the table have to be filtered out.

**Type identity across compilation units.** gcc numbers types per compilation unit, so the same
`std::string` appears as a different `(cu,n)` in every unit that includes it, each with its own
body. The importer content-hashes the parsed bodies and canonicalises, which is what collapses a
corpus of thousands of near-duplicate definitions down to one datatype each. Divergent
collisions — the same name with genuinely different bodies — are detected and kept apart rather
than merged.

**Attribution — where a type ends up in the tree.** Stabs say which source files *mentioned* a
type, never which one owns it, so the owning file is inferred. In precedence order:

1. **C++ scope from the mangled name.** A method-bearing class is filed under its namespace as a
   category, named by its own leaf. This is deliberately the exact slot Ghidra's demangler would
   create for a `this` parameter — filling that slot means the two agree instead of forking into
   a real type beside an empty placeholder.
2. **Compilation-unit-local anonymous types** → that unit's path plus `/anon`.
3. **Standard library** → `/std/<path after the stdlib marker>`, so `bits/stl_vector.h` files
   identically no matter which toolchain prefix it was included through.
4. **A real header wins over a `.cpp`.** gcc's include bracketing surfaces sibling `.cpp` files
   as if they were headers; `.h/.hpp/.hh/.hxx/.tcc` beat them.
5. **One defining source** → that file's path.
6. **Several sources, no header owner** → the lexicographically first, suffixed `/multi`. A hint
   map built from the majority source line of the class's own member functions is consulted
   first, since that usually names the real header gcc failed to bracket.

Paths are normalised on the way in — drive letters dropped, `/` and `\` both honoured, `..`
collapsed — and the longest prefix common to every compilation unit is stripped so categories
start at the project root rather than at the build machine's directory layout. Each decision is
recorded in an attribution trace, so a type in a surprising place can be explained rather than
guessed at.

Other fixed locations: constants at `/stabs/constants/<namespace>/size_Nb`, unnamed aggregates at
`/stabs/unnamed`, the decoded `.stab` overlay types at `/stabs`, and vtable structs under the
class's own category.

**Type grammar.** Descriptor dispatch covers `*` `&` `k` `B` `a` `e` `s` `u` `Y` `f` `#` `r` `R`
`x` `@` plus bare and parenthesised type references. Two of those are GNU extensions absent from
the Sun spec: `#` (pointer-to-member-function) and `@s<bits>` (size attribute, which gcc emits on
`_Bool` and `long long` where the range bounds alone don't pin the width). Forward references
(`x` + `s`/`u`/`c`/`Y`) are resolved back to their definitions; gcc's `c` and `Y` kinds are its
own additions to Sun's `e`/`s`/`u`.

**C++ encodings.** The inheritance list (`!<count>,<virt><access><offset>,<base>;`), the method
block with its access/virtuality markers, and the trailing `~%<type>;` vptr-basetype section that
marks a class polymorphic and names the base owning the vptr. gcc 3.x emits `s` for both `struct`
and `class`, so the importer promotes to "class" on the evidence — any method, or any non-public
base. Vtable layout follows the Itanium ABI, modelled as a single flat vtable — which does not
cover every multiple-inheritance case.

**Register numbering.** Register variables carry gcc's `dbx_register_map` numbers, which are
*not* the DWARF numbers — the two disagree on `%ebp`/`%esp` (stabs: 4 and 5; DWARF: the reverse).
Ghidra ships only the DWARF spelling, so the map is reimplemented in `parse/DbxRegisters.kt`.

**Constants.** Addressless `:c=` constants have no storage to attach to, so they're applied as
equates under their qualified name and collected into `/stabs/constants/<namespace>/size_Nb` enum
datatypes, bucketed by the minimal width that holds the value.

**Static data members** carry a linkage name in the member declaration and no address stab of
their own — that name is the only link back to the emitted symbol, and it's what lets the global
be typed from the class declaration instead of left to the demangler.

**The `.stab` section itself** can be overlaid with one decoded `StabRecord` struct per 12-byte
entry, with references into `.stabstr` and back to the code or data each record describes —
useful for reading the raw debug info in the Listing.

**Format limits.** Line numbers past 65535 are unrepresentable (the `desc` field is 16 bits, and
gcc has no escape for it — Sun's `N_XLINE` exists for this and gcc never emits it). `using`
declarations and directives leave no trace at all. Bitfields are currently laid at their
containing byte rather than as bitfields.

---

## Bibliography

**The format.** There is no standard — stabs is a semi-documented convention, and the two
manuals disagree with each other and with what gcc emits.

- *STABS Debug Format*, Menapace, Kingdon & MacKenzie (Free Software Foundation) — the GNU
  reference, distributed with gdb.
  [HTML](https://sourceware.org/gdb/onlinedocs/stabs.html/) ·
  [PDF](https://sourceware.org/gdb/onlinedocs/stabs.pdf)
- *Stabs Interface*, Sun Microsystems (Sun Studio 11) —
  [PDF](https://web.archive.org/web/20061115071332/http://dsc.sun.com/sunstudio/documentation/ss11/stabs.pdf). Describes constructs
  gcc never emits, and omits GNU extensions gcc emits constantly.
- [Stabs](https://en.wikipedia.org/wiki/Stabs) on Wikipedia, for orientation.

**The implementations**, which settle what a real binary actually contains when the manuals
disagree.

- [`gcc/dbxout.c`](https://gcc.gnu.org/git/?p=gcc.git;a=history;f=gcc/dbxout.c;hb=refs/tags/releases/gcc-12.3.0)
  — the emitter. Deleted in gcc 13; the link is pinned to 12.3.0, the last release that has it.
- [`gdb/stabsread.c`](https://sourceware.org/git/?p=binutils-gdb.git;a=history;f=gdb/stabsread.c;hb=refs/tags/gdb-12.1-release)
  — the reader. Also since removed from gdb.
- [`include/aout/stab.def`](https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=include/aout/stab.def)
  — the record-type table, still in binutils.
- [gcc 3.1 release notes](https://gcc.gnu.org/gcc-3.1/changes.html) — "The default debugging
  format for most ELF platforms … has changed from stabs to DWARF2."

**Prior art.**

- [RidgeX/ghidra-gcc2-stabs](https://github.com/RidgeX/ghidra-gcc2-stabs) — a Ghidra script
  parsing GCC 2.x stabs.
- [chaoticgd/ccc](https://github.com/chaoticgd/ccc) — library and tools for debugging symbols in
  PS2 games, focused on STABS in `.mdebug` sections.
- [uyjulian/stab_debuginfo_utils](https://github.com/uyjulian/stab_debuginfo_utils) — STAB
  debug information utilities, for x86 and r3000 MIPS.
