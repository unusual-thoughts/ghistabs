package ghistabs

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.util.task.TaskMonitor
import java.io.File

/**
 * 12.0+: `ProgramLoader`. Imports [binary], hinting the [compiler] spec (null leaves the loader its
 * own preference). The caller owns the result and must [close][ghistabs.LoadedProgram.close] it — prefer
 * [ghistabs.withProgram] when the program's life is a single scope.
 */
fun Any.loadProgram(binary: File, compiler: String? = "gcc", log: MessageLog? = null, monitor: TaskMonitor? = null) =
    ProgramLoader.builder()
        .source(binary)
        .apply {
            if (compiler != null) compiler(compiler)
            if (monitor != null) monitor(monitor)
            if (log != null) log(log)
        }
        .let { builder ->
            builder.load().primary.getDomainObject(this).let { program ->
                program.release(builder)
                LoadedProgram(program, this)
            }
        }
