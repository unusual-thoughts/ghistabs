# Vtable Resolution Failure Buckets

This document explains each diagnostic bucket for vtable resolution failures (AC5.3).
Each bucket represents a category of classes that could not be resolved to a `_ZTV` symbol,
despite evidence of polymorphism (virtual methods or vtable-pointer markers).

## Buckets

### `templated-unsupported`

**Meaning:** The class name contains template parameters (e.g., `std::vector<int>`, `MyClass<T>`).

**Why not actionable in v1:** Itanium name mangling for templated classes requires sophisticated
template specialization parsing. The mangling depends on the exact template arguments at the
point of instantiation, making static symbol resolution unreliable without resolving the
full specialization chain. Cygwin/PE name encoding for template classes is also variable
across compiler versions.

**Resolution path (v2+):** Extend `itaniumMangleClassName` to parse and encode template parameters,
or use a heuristic symbol-iterator scan that tries multiple mangling candidates per template
instantiation pattern.

### `truly-missing`

**Meaning:** No symbol matching any of the candidate names was found in the symbol table,
and no pattern match was found in `.rdata` section.

**Why not actionable in v1:** This indicates either:
1. The binary was stripped or the vtable symbol was removed (e.g., link-time optimization).
2. The compiler used a non-standard or unknown vtable naming convention not covered
   by Itanium, Cygwin/PE, or gcc2 variants.
3. The symbol resolv was disabled in a compilation flag.

Classes in this bucket are marked for manual review; they appear polymorphic but
their vtables are not recoverable through symbol lookup alone.

**Resolution path (v2+):** Consider heuristic vfptr-value scanning: if a class has a vfptr field
at offset 0, scan the memory region it points to and look for recognizable vtable structure
(pointers to known function addresses). This requires additional context unavailable in v1.

### `no-virtual-methods-flagged-but-marker-set`

**Meaning:** The class has `hasVTablePointerMarker = true` (from STABS `~%<id>;` directive)
but contains no virtual method declarations (`methods.none { virt == VIRTUAL }`).

**Why not actionable in v1:** This mismatch suggests either:
1. A stabs parser defect: virtual methods were not correctly extracted.
2. A compiler edge case: a vtable is present but all virtual method definitions
   were optimized away or inlined.
3. Inherited-only polymorphism: the class inherits virtual methods from a base,
   and the base's vtable is being referenced via the marker (handled by inheritance
   logic in Task 5).

Since the root cause is ambiguous, placing the class in this bucket allows
manual analysis or a second pass with enhanced virtual-method detection.

**Resolution path (v2+):** If `hasVTablePointerMarker` is set, assume the class is polymorphic
even if no virtual methods are present. This is a safe conservative assumption.

## Summary

No action is required for classes in any of these buckets in v1. They are:
- **Diagnosed** via counter and logging.
- **Bucketed** for visibility in the diagnostics report.
- **Deferred** to v2+, where extended symbol resolution, template handling, and
  heuristic vtable scanning can improve coverage.

The goal of v1 is ≥80% resolution rate, acknowledging that some edge cases will remain
unresolved. Future phases can refine coverage incrementally.
