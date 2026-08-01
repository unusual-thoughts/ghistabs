# ghidra-stabs

A Ghidra extension that imports [**STABS**](https://sourceware.org/gdb/onlinedocs/stabs.pdf) 
debug info (`.stab` / `.stabstr`) into a program:
data types, function signatures, parameters and locals, C++ classes and vtables, constants and
static members. On top of the import it can reconstruct, per source file, a line-aligned
**source skeleton** or an annotated **decompilation**.

Written for the debug info gcc 2.9x–3.4 emits for Cygwin/MinGW PE binaries — the case where
Ghidra has no importer at all (its DWARF and PDB loaders don't apply, and the stabs are just
two opaque sections). Development target is Cygwin **gcc 3.4.4** PE; x86-64 ELF binaries built
with `-gstabs` also parse and import.

## What it recovers

| From the stabs                        | What lands in the program                                                             |
| ------------------------------------- | ------------------------------------------------------------------------------------- |
| Type definitions (`N_LSYM`, cross-CU) | Structs, unions, enums, typedefs, pointers, arrays, function pointers in the DTM       |
| Function stabs (`N_FUN`)              | Return type + parameter signature, demangled names, correct calling convention         |
| `N_PSYM` / `N_LSYM` / `N_RSYM`        | Stack and register locals and parameters, with their real names and types              |
| `N_LBRAC` / `N_RBRAC`                 | Lexical scope plate comments                                                           |
| C++ class stabs                       | Class namespaces, this-typed methods (`__thiscall`), base-class embedding, Itanium vtable structs applied at `_ZTV` |
| `:c=` constants, static data members  | Equates and reconciled globals                                                         |
| `N_SO` / `N_SOL` / `N_SLINE`          | Per-source-file line map, driving the skeleton/decompilation render                    |
| `.stab` section itself                | An optional decoded `StabRecord` overlay, one struct per record, cross-referencing `.stabstr` and the code/data each record describes |

## Install

Grab the zip matching your Ghidra version from `dist/`, then either

- **Ghidra GUI:** `File > Install Extensions… > +`, pick the zip, restart Ghidra; or
- **Gradle:** `./gradlew installExtension` (builds and unpacks straight into your Ghidra user
  extensions dir, e.g. `~/.config/ghidra/ghidra_12.1.2_DEV/Extensions`; set `GHIDRA_USER_DIR`
  to override), then restart Ghidra.

Requires Ghidra 12.x and a JDK 21 toolchain. An extension zip only loads into the Ghidra
release it was built against.

## Build

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

| Option                                    | Default | Effect                                                                                                                  |
| ----------------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Reconstruct C++ classes**               | on      | Class namespaces, this-typed member methods, `<Class>_vftable` structs at `_ZTV`. Off leaves plain structs — member calls lose `this`/args and virtual calls stay unresolved. |
| **Apply scope plate comments**            | on      | Plate comments at lexical scopes where `N_LBRAC`/`N_RBRAC` info exists.                                                   |
| **Shorten templated names via typedefs**  | off     | Rename long templated types onto their shorter aliases (`basic_string<char, …>` → `string`), recursively inside other templates. |
| **Fold source-file spellings**            | on      | Collapse gcc's two spellings of one physical header (full include path vs bare `#include "x.h"`) onto one rendered output file, by unique basename. |
| **Overlay `.stab` section structs**       | on      | Decode every `.stab` entry into a `StabRecord` struct with references into `.stabstr` and back to the code/data it describes. |
| **Minimum log level**                     | `INFO`  | Floor for diagnostics written to the analysis log. Bookmarks and counters are emitted regardless.                          |

Diagnostics land in three places: the analysis **MessageLog** (filtered by the log level),
an **`Analysis` bookmark** at every addressed diagnostic, and a summary of counters at the
end of the import.

### `Tools > Stabs`

- **Re-import** — clears the `Stabs Imported` flag and re-runs auto-analysis, so the importer
  runs again over the current program. Use it after changing analyzer options.
- **Export decompilation…** — asks for a target folder and writes the reconstructed
  decompilation there, one file per source file, with gcc SjLj exception scaffolding elided.
  Requires the importer to have run first.

Both actions are enabled only when the program actually has `.stab`/`.stabstr` blocks.

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
build/cli/ghidra-stabs skeleton unbouniaf.exe -d out/skeletons
build/cli/ghidra-stabs decomp   unbouniaf.exe -d out/decomps --shorten-typedefs
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

| Option                    | Default   | Effect                                                                       |
| ------------------------- | --------- | ---------------------------------------------------------------------------- |
| `-d`, `--target-dir`      | required  | Output directory; one file per source, named from the source path.            |
| `--classes` / `--no-classes` | on     | Same as the analyzer's class reconstruction.                                  |
| `--shorten-typedefs`      | off       | Same as the analyzer's typedef shortening.                                    |
| `--fold-sources` / `--no-fold-sources` | on | Same as the analyzer's source folding.                                  |
| `-v`, `--log-level`       | `INFO`    | `DEBUG`/`INFO`/`WARN`/`ERROR`; the log streams live to stderr.                |
| `--log FILE`              | stderr    | Redirect the import log to a file.                                            |
| `--disable-analyzer NAME` | —         | Turn off every analyzer whose name contains `NAME` (repeatable). Render the same binary with and without one to A/B what it changes. |
| `--records-json`, `--harvest-json`, `--registry-json` | — | Dump the parsed stab records / harvest / materialized type registry as JSON. |
| `--degradation-log FILE`  | —         | Grouped report of every type that materialized to something weaker than the stabs described. |

## Status

The importer is the mature part; skeleton and especially decompilation rendering are usable
but still under active work — see `docs/notes/render-backlog.md` for known output issues.

## Development

`CLAUDE.md` (repo orientation and conventions), `TESTING.md` (test tiers and flags),
`docs/kotlin-style.md` (house style), `docs/notes/` (design notes and backlogs).
