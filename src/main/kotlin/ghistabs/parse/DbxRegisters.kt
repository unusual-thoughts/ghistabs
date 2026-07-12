package ghistabs.parse

private val X86_DBX_TO_REGISTER = listOf("EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI")
private val X86_64_DBX_TO_REGISTER = listOf(
    "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
)

/**
 * Map a gcc dbx register number to its architecture register name for the given [pointerSize].
 * Arch-specific (gcc/config/<arch>/<arch>.h `DBX_REGISTER_NUMBER`). i386 (ptr=4): 0..7 =
 * eax,ecx,edx,ebx,esp,ebp,esi,edi. x86_64 (ptr=8, SysV+Win64 agree): 0..7 =
 * rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp; 8..15 = r8..r15.
 */
fun dbxRegisterName(pointerSize: Int, dbxNum: Int): String? = when (pointerSize) {
    4 -> X86_DBX_TO_REGISTER
    8 -> X86_64_DBX_TO_REGISTER
    else -> null
}?.getOrNull(dbxNum)
