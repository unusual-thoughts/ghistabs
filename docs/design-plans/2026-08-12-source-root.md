# Source files: port onto `ghidra.program.model.sourcemap`, then use a source root as ground truth

Draft, 2026-08-12. Two things at once, in that order: **replace our hand-rolled source-file identity
and line-map management with `ghidra.program.model.sourcemap`**, and then take an optional **source
root** as ground truth for the four uses §44 measured. The port is not a mirror — the goal is that
Ghidra owns what a source file is and where each address came from, and that our spelling
canonicalisation, basename folding and `String`-keyed indices are deleted rather than kept in step.
It is also what makes the second half small: nearly every piece it needs turns out to exist already.

## Why

§44 graded unpackfile against libstdc++ 3.2.3 itself. Two facts drive everything:

| | |
| --- | --- |
| inlined stretches naming a libstdc++ file | 392 occurrences, **100% land on real code**, 94% inside a function whose name the source gives |
| declarations with ground truth | 185: **63% right line**, 5% right file/wrong line, 29% wrong file, 2% past EOF |
| misfiled declarations | 48 distinct, **24 declared at the very same line in another file** |

**The line is usually right and the file is usually wrong.** So a source root identifies files; it must
never "correct" a line. And **a file's real length is knowable**, which is the input §43's circular
extent problem lacks.

The second why is platform alignment. Ghidra 12.1 models source files first-class, and **DWARF and PDB
both publish into it** (`DWARFImporter.processSourceMaps`, PDB's `ApplyLineNumbers`). Stabs is the odd
provider out: we parse N_SLINE into `Harvest.lineEntries` and keep it to ourselves, so none of the
program-level machinery — the Source Files table, the listing's source-map field, transforms,
`ProgramDiff`/`ProgramMerge` — sees anything.

## The platform already models this

| we have | Ghidra has | notes |
| --- | --- | --- |
| `LineEntry(source, line, addr)` in `Harvest.lineEntries` | `SourceMapEntry` + `SourceFileManager.addSourceMapEntry(file, line, addr, length)` | published with **length 0**: stabs records points, and the disjoint-or-identical rule binds only ranged entries |
| source spellings as raw `String` everywhere | `ghidra.program.database.sourcemap.SourceFile` — URI-normalised path, `SourceFileIdType`, identifier | value class, no Program needed, so it is usable in pure tests |
| §15 basename folding of two spellings onto one file | `SourceFileManager.transferSourceMapEntries(from, to)` | the platform's own answer to the same problem |
| `linesBySource` line→address lookups | `getSourceMapEntries(file, minLine, maxLine)` | indexed by the DB |
| `activityExtent`'s "how far does this file reach" | `SourceFileUtils.getSourceLineBounds(program, file)` | min/max mapped line, straight from the program |
| a `--source-root` mapping recorded paths to local ones | `SourcePathTransformer.addDirectoryTransform(recordedDir, localDir)` + `UserDataPathTransformer` | persisted in user data, **already has a GUI** (Source Files and Transforms) |
| path spellings with `\`, drive letters, bare names | `SourceFileUtils.normalizeDwarfPath(path, baseDir)` | documents MinGW backslashes explicitly; relative paths get an artificial root |
| nothing | `SourceFilesTablePlugin`, `SourceMapFieldFactory` | free the moment we publish |

## What still has to be ours, and why

**Ghidra has no C++ front end.** `ghidra.app.util.cparser.C`'s complete keyword token list is `auto
break case char continue default do double else enum extern float for goto if int long register return
short sizeof static switch typedef union unsigned void while` plus `__attribute/__declspec/…` — no
`class`, `template`, `namespace`, `operator`, `::`. It tracks provenance internally
(`headerFileName`/`headerFileLine`, `C.jj:123-125`) but only to format parse messages, and no result
carries a line. So "which function encloses `stl_vector.h:123`" cannot be answered by it.

That leaves exactly one hand-rolled component: a **declarator index** over source text — strip comments
and strings, match braces, record `(name, startLine, endLine)`. Pure, ~150 lines, Kind-1 testable, and
it never has to *understand* C++, only find heads and matching braces.

Its input, though, should be the platform's: `ghidra.app.util.cparser.CPP.PreProcessor` has no grammar
to choke on, resolves `#include`s the way the compiler did (`addIncludePaths`, `CPP.jj:883-935`), and
emits `#line <n>: "<file>"` at every file switch (`CPP.jj:1635-1684`) — so its output carries
provenance **and contains only the branches that compiled**. The catch: `bits/c++config.h` is generated
at build time and absent from a source tarball, so preprocessing is an *input strategy* with raw
reading as the fallback, not a dependency.

## Port strategy

Three layers, each shippable, each leaving the render working.

**1. Adopt the identity, delete ours (model-side).** Raw source strings become `SourceFile` handles
everywhere identity is meant, and our spelling machinery goes with them: `canonicalizeSourcePaths`,
the ad-hoc basename/drive-letter handling, the `String`-keyed maps. Our `parse.SourceFile` survives
only as the CU-vs-header *distinction* (§43 depends on it), keyed by the Ghidra handle. What does
**not** move is declaration attribution — `effectiveSourceFor`, the hints, the conflict sets — which
answers a different question and stays ours.

**2. Give the program the line map (write-side), derive the render's index from it.** Every N_SLINE
becomes a `SourceMapEntry`, mirroring `DWARFImporter`; §15's folds become `transferSourceMapEntries`.
The render's `linesBySource` stops being a second authority and becomes a cache read back from the
program. **Published with length 0**, because the API's rule — entries with non-zero lengths must be
disjoint or identical — only binds ranged entries, and stabs records points: several line numbers at
one address are legal, and inventing gap-derived ranges would be an interpretation that interleaved
inlined code makes wrong half the time.

**3. Consume (read-side).** `getSourceLineBounds` feeds the extent; the path transformer resolves a
spelling to a local file; the declarator index answers the C++ question. This is where the four uses
land.

## The four uses, expressed against the platform

1. **Name the inlined stretches** — `enclosing(transformedPath, line)` from the declarator index;
   `__inline_stl_vector_h_123` → `_M_deallocate__stl_vector_h_123`. 94% resolvable per §44.
2. **Re-attribute misfiled declarations** — a reverse `(name, line) → files` map over the root; accept
   only unique answers. Moves 24 of unpackfile's 48 misfiled declarations to files that actually
   declare them.
3. **A real extent** — the local file's line count where the root has it, `getSourceLineBounds` where it
   does not. §43's gap heuristic is then unnecessary wherever a root exists.
4. **An attribution scorecard** — §44 as counters plus an itemised dump, so an attribution change is
   graded automatically instead of by hand. Item 9 shipped a silent content loss precisely because this
   did not exist.

## `DefineTable`: the macros stabs never had

`PreProcessor.getDefinitions()` returns a `DefineTable` that survives the run, and it is worth more
than the "macros → equates" footnote it had in the first draft. Stabs records **no macros at all** — a
reconstructed header today cannot show a single `#define` — so this is not a better version of
something we have, it is a category of content we are missing entirely.

What it exposes:

| | |
| --- | --- |
| `getDefineNames()`, `getValue(name)`, `expandDefine(name)` | the name and its *expanded* text, macros-within-macros resolved |
| `isNumeric`, `getCValue`, and `ExpressionEvaluator` inside `populateDefineEquates` | so `(1 << 3) | 4` evaluates, not just literals |
| `isArg(name)`, `getArgs(name)`, `toString(name)` | function-like macros, with their parameter list |
| `getDefinitionPath(name)` | **which file defined it** |
| `get(name)` → `PPToken extends Token` | carries `beginLine` **and** `path` — so a macro has a line, not just a file |
| `populateDefineEquates(openDTMgrs, dtMgr)` | one-member `EnumDataType` named `define_<NAME>`, filed under `<file>/defines`, resolved against open archives |

Three uses follow, in value order:

1. **Named constants in the decompiler.** A magic number in a decompiled body that matches a macro
   value can be applied as that macro — the one-member-enum idiom `populateDefineEquate` already
   builds, which is how Ghidra models "this scalar is really this named constant". This is the
   RE-facing win and it is one call.
2. **`#define`s in the reconstructed header**, at their true line, because `PPToken` keeps
   `beginLine`. A header view that currently shows types, functions and globals would show its macros
   too — content no stabs-only render can produce.
3. **Ground truth for conditional compilation**, which is what makes phase 4's preprocessed text
   authoritative rather than one plausible reading of the `#ifdef`s.

**The constraint that decides the shape:** one `EnumDataType` per macro, and libstdc++ plus MinGW's C
headers define thousands. Applying all of them would bloat the program's type manager for no reading
benefit. So it is opt-in and filtered — a macro is worth materialising when its value occurs as a
scalar operand in the program, or when it was defined in a file the render emits. Measure the count
before choosing the filter.

**Not a version guard.** `__GNUC__` is a compiler built-in and `_GLIBCPP_VERSION` lives in the
*generated* `c++config.h`, so neither is in a source tarball. The version evidence is elsewhere and
simpler: the recorded include path **names it** — `c:/mingw/include/c++/3.2.3/bits/stl_vector.h`.
Checked on the fixtures: they carry no `.comment` section and no `GCC: (GNU) …` producer string at all,
so the path is the only version fact available, and it is enough to reject a mismatched root up front,
before the per-file agreement guard does its finer-grained work.

## Risks, and what is deliberately not done

- **`SourceFile` validates paths.** Non-blank, URI-normalisable, no trailing `/`, absolute after
  normalisation. Our spellings include `E:/work/…`, `c:/mingw/…` and bare `dspinfo.h`.
  `normalizeDwarfPath(path, baseDir)` is built for exactly this, but the drive-letter case must be
  verified in phase 1, not assumed — a throw per file is the failure mode, and DWARF's importer catches
  and skips, which we must not silently copy.
- **DB growth.** unpackfile has thousands of line entries; xmltest far more. Publishing is a write per
  entry. Measure before enabling by default; it is an option if it is costly.
- **What "unchanged" means for the port.** Content, not bytes-on-paths. Normalising spellings through
  `SourceFile` moves output files (separators, a synthetic root where a drive letter will not form a
  URI), so the phases compare by file *identity* with the rename mapping printed, and require zero
  content difference. Demanding byte-identical paths would force our old spelling policy to be
  reimplemented on top of Ghidra's identity — keeping alive exactly what the port deletes. The feature
  phases (5–9) do change output by design; there the byte-identical gate applies to the *no root
  configured* path, which must stay inert.
- **`LineEntry` is implemented, not deleted.** `SourceMapEntry` is an interface with our record's exact
  shape, so the parse-time record implements it and the DB becomes a second producer of one type. That
  keeps the harvest dumps and the Program-less unit tests working, which a DB-only model would not.
- **Not "trust the source over the stabs".** The root corrects files, never lines.
- **Not fuzzy matching.** A file declares that name at that line or it does not; ambiguity is reported.
- **Not on by default** for the root. No root, no behaviour change, and every backlog measurement stays
  comparable.

## Open questions

- ~~Does `normalizeDwarfPath` accept `c:/mingw/include/c++/3.2.3/bits/stl_vector.h`, or does the drive
  letter need handling of our own?~~ **Answered (phase 1, task 1): it accepts every shape we have, and
  no drive-letter handling of our own is needed.** `normalizeDwarfPath(path, "stabs")` gives
  `c:/mingw/…` → `/c:/mingw/…` (the colon survives — a URI is happy with one once the path is rooted),
  `C:\work\include\foo.h` → `/C:/work/include/foo.h`, `dspinfo.h` → `/dspinfo.h`, `./local.h` →
  `/stabs/local.h`, `../../interface/…` → `/stabs_2/interface/…`. Nothing throws, so nothing is
  skipped. Raw `new SourceFile(path)` throws on all but an already-absolute forward-slash path
  ("Relative path in absolute URI"), so every construction routes through `normalizeDwarfPath`.
- Whether a *ranged* view should also be published for the listing field's benefit, given entries are
  points. Look at the listing with points first.
- Whether address-range membership reproduces `Func.lineEntries`' stab-order membership, which is
  documented as authoritative and includes landing pads Ghidra's CFG body omits. Proven per fixture
  before the old path is deleted, not assumed.
- Do we record an identifier? `SourceFileIdType.MD5` describes the file the compiler read, which stabs
  does not tell us. gcc's `N_BINCL` checksum is a per-CU sum over the header's stabs, not a file hash —
  worth investigating later as a same-header check, not as a file identity.
- Hot-path cost: the render's per-row `lastOrNull { addr <= a }` becomes a backward
  `getSourceMapEntryIterator`. Read once into a cache per render rather than per query, and measure.
