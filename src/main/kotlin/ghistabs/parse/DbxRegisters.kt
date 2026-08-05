package ghistabs.parse

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

/**
 * Map a gcc dbx register number to its architecture register name for the given [pointerSize].
 * Arch-specific (gcc/config/<arch>/<arch>.h `DBX_REGISTER_NUMBER`). i386 (ptr=4): 0..7 =
 * eax,ecx,edx,ebx,ebp,esp,esi,edi. x86_64 (ptr=8, SysV+Win64 agree): 0..7 =
 * rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp; 8..15 = r8..r15.
 *
 * Deliberately not covered: i386 12..19 are the x87 stack (`st(0)`..`st(7)`) and 21..28 the SSE
 * registers. They arrive on `long double` locals in libstdc++'s float conversions and are reported
 * as `reglocal-unmapped-regnum` rather than mapped, because Ghidra's ST0 is 80-bit and binding a
 * narrower local to it needs sizing work this doesn't do.
 *
 * ELF/i386 would need `svr4_dbx_register_map` instead (ebp/esp back the DWARF way round); no such
 * fixture exists — the ELF ones are x86-64, which uses one map for both formats.
 */
fun dbxRegisterName(pointerSize: Int, dbxNum: Int): String? = when (pointerSize) {
    4 -> X86_DBX_TO_REGISTER
    8 -> X86_64_DBX_TO_REGISTER
    else -> null
}?.getOrNull(dbxNum)

/**
 * Where gcc put a variable, as the scope plate comments spell it: `EBX` for a register,
 * `Stack[-0x38]` for a frame slot. [rawValue] is the stab's value field — a dbx register number or a
 * gcc frame offset — and [frameBias] converts the latter to Ghidra's origin.
 *
 * Shared so the render and the plate comments cannot drift into two spellings of one fact.
 */
fun dbxStorageName(pointerSize: Int, rawValue: Int, register: Boolean, frameBias: Int): String = if (register) {
    dbxRegisterName(pointerSize, rawValue) ?: "r$rawValue"
} else {
    (rawValue - frameBias).let { if (it < 0) "Stack[-0x${(-it).toString(16)}]" else "Stack[0x${it.toString(16)}]" }
}
