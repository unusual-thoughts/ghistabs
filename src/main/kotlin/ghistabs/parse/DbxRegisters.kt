package ghistabs.parse

import ghidra.program.model.listing.Program

// gcc's `dbx_register_map` — the *stabs* map, which is NOT the DWARF one. They differ exactly at
// %ebp/%esp: stabs calls ebp 4 and esp 5, DWARF the reverse (gcc keeps them as two tables,
// dbx_register_map vs svr4_dbx_register_map; gdb as i386_dbx_reg_to_regnum vs
// i386_svr4_dwarf_reg_to_regnum, and installs the former for non-ELF i386 — our Cygwin PE corpus).
// Ghidra ships the DWARF spelling in x86/data/languages/x86.dwarf; do not copy it here.
private val X86_DBX_TO_REGISTER = listOf("EAX", "ECX", "EDX", "EBX", "EBP", "ESP", "ESI", "EDI")
private val X86_64_DBX_TO_REGISTER = listOf(
    "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
)

// SPARC's map is the identity — `DBX_REGISTER_NUMBER(REGNO) (REGNO)` in gcc/config/sparc/aout.h
// (sol2.h and linux.h agree bar the flat-model %i7 case), and Sun's own compiler matches it. So the
// number is the hardware register: 0..7 %g, 8..15 %o, 16..23 %l, 24..31 %i. Ghidra names %o6 `sp`
// and %i6 `fp`.
private val SPARC_DBX_TO_REGISTER = listOf(
    "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7",
    "o0", "o1", "o2", "o3", "o4", "o5", "sp", "o7",
    "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
    "i0", "i1", "i2", "i3", "i4", "i5", "fp", "i7",
)

/** Which target's `DBX_REGISTER_NUMBER` map applies. The number alone doesn't say. */
enum class DbxArch { X86, X86_64, SPARC }

/** [Program]'s map. Pointer size can't pick it alone: i386 and SPARC are both 4 bytes wide. */
val Program.dbxArch: DbxArch? get() = when (language.processor.toString()) {
    "x86" -> if (defaultPointerSize == 8) DbxArch.X86_64 else DbxArch.X86
    "Sparc" -> DbxArch.SPARC
    else -> null
}

/**
 * Map a dbx register number to its architecture register name (gcc/config/<arch>/<arch>.h
 * `DBX_REGISTER_NUMBER`). i386: 0..7 = eax,ecx,edx,ebx,ebp,esp,esi,edi. x86_64 (SysV+Win64 agree):
 * 0..7 = rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp; 8..15 = r8..r15. SPARC: identity over %g/%o/%l/%i.
 *
 * Deliberately not covered: i386 12..19 are the x87 stack (`st(0)`..`st(7)`) and 21..28 the SSE
 * registers; SPARC 32..63 are %f0..%f31. They arrive on `long double` locals in libstdc++'s float
 * conversions and are reported as `reglocal-unmapped-regnum` rather than mapped, because Ghidra's
 * ST0 is 80-bit and a SPARC `double` spans two `fs` registers — binding a local across either needs
 * sizing work this doesn't do. (The SunOS corpus only allocates 24..29, the argument window.)
 *
 * ELF/i386 would need `svr4_dbx_register_map` instead (ebp/esp back the DWARF way round); no such
 * fixture exists — the ELF ones are x86-64, which uses one map for both formats.
 */
fun DbxArch.registerName(dbxNum: Int): String? = when (this) {
    DbxArch.X86 -> X86_DBX_TO_REGISTER
    DbxArch.X86_64 -> X86_64_DBX_TO_REGISTER
    DbxArch.SPARC -> SPARC_DBX_TO_REGISTER
}.getOrNull(dbxNum)

fun Program.dbxRegisterName(dbxNum: Int) = dbxArch?.registerName(dbxNum)

/**
 * Where the compiler put a variable, as the scope plate comments spell it: `EBX` for a register,
 * `Stack[-0x38]` for a frame slot. [rawValue] is the stab's value field — a dbx register number or a
 * frame offset — and [frameBias] converts the latter to Ghidra's origin.
 *
 * Shared so the render and the plate comments cannot drift into two spellings of one fact.
 */
fun DbxArch.storagename(rawValue: Int, register: Boolean, frameBias: Int): String = if (register) {
    registerName(rawValue) ?: "r$rawValue"
} else {
    (rawValue - frameBias).let { if (it < 0) "Stack[-0x${(-it).toString(16)}]" else "Stack[0x${it.toString(16)}]" }
}
