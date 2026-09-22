package ghistabs

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.util.task.TaskMonitor
import java.io.File

/**
 * 12.0+: `ProgramLoader`. Imports [binary], hinting the [compiler] spec where the file's own loaders
 * offer one (see [ghistabs.offersCompilerSpec]; null leaves the loader its own preference) and, for
 * the loaders that take one, the [baseAddress] to load at. The caller owns the result and must
 * [close][ghistabs.LoadedProgram.close] it — prefer [ghistabs.withProgram] when the program's life
 * is a single scope.
 */
fun Any.loadProgram(
    binary: File,
    compiler: String? = "gcc",
    log: MessageLog? = null,
    monitor: TaskMonitor? = null,
    baseAddress: Long? = null,
) = ProgramLoader.builder()
    .source(binary)
    .apply {
        if (compiler != null && binary.offersCompilerSpec(compiler)) compiler(compiler)
        if (monitor != null) monitor(monitor)
        if (log != null) log(log)
        if (baseAddress != null) addLoaderArg(BASE_ADDR_LOADER_ARG, "0x${baseAddress.toString(16)}")
    }
    .let { builder ->
        builder.load().primary.getDomainObject(this).let { program ->
            program.release(builder)
            LoadedProgram(program, this)
        }
    }
