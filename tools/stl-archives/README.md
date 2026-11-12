# MSVC STL type archives

Ghidra data type archives (`.gdt`) of the MSVC standard library layouts, one per runtime, architecture
and CRT: `msvcp140_x86.gdt`, `msvcp140d_x64.gdt`, `msvcp90_x86.gdt` and so on. Types are named and
filed where Ghidra's Microsoft demangler puts a class (`/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>`),
so the `this` of a demangled `std::` method matches the archive type by path: the demangler's
placeholder is that path under `/Demangler`.

The [`MSVC STL archives`](../../.github/workflows/stl-archives.yml) workflow builds them and uploads
them as the `msvc-stl-archives` artifact:

| Archive | Source | Check |
| --- | --- | --- |
| `msvcp140_{x86,x64}` | [`stl_probe.cpp`](stl_probe.cpp) built with `/MD` on the runner's Visual Studio | same sizes and field offsets as Microsoft's public `msvcp140` PDB, for every type both define |
| `msvcp140d_{x86,x64}` | the probe built with `/MDd` (`_ITERATOR_DEBUG_LEVEL=2`) | |
| `msvcp90_{x86,x64}` | Microsoft's public PDB of msvcp90 9.0.30729.9619, the last security rebuild | |

msvcp90 covers what the DLL itself instantiates (strings, iostreams, locale and facets, exceptions),
not header-only containers, and has no debug variant: neither needs more than a VS2008 toolchain
running the same probe.

## Building one yourself

`ghidra_scripts/MsvcStlArchiveScript.java` ships with the extension. Run it from the Script Manager on
any program of the right architecture and point it at a PDB with type information, or headless:

```
tools/stl-archives/run.sh archive out.gdt <program> <pdb>
tools/stl-archives/run.sh compare <program> out.gdt reference.gdt
```

Which runtime builds have typed public PDBs is not obvious: for msvcp80 and msvcp90 only the 2016 to
2019 security rebuilds do, for msvcp100 build 40219.325 but not 40219.1, and msvcp60's are stripped.
[`pdb_url.py`](pdb_url.py) prints the symbol server URL of a DLL's PDB.
