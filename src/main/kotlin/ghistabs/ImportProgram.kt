package ghistabs

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.util.task.TaskMonitor
import java.io.File

/**
 * Imports [binary], hinting the [compiler] spec where the file's own loaders offer one (see
 * [offersCompilerSpec]; null leaves the loader its own preference). The caller owns the result and
 * must [close][LoadedProgram.close] it - prefer [withProgram] when the program's life is a single scope.
 *
 * `load()` holds what it loads with the builder as consumer, so the program is taken over with a
 * reference of our own and the builder's is dropped.
 */
fun Any.loadProgram(binary: File, compiler: String? = "gcc", log: MessageLog? = null, monitor: TaskMonitor? = null) =
    ProgramLoader.builder()
        .source(binary)
        .apply {
            if (compiler != null && binary.offersCompilerSpec(compiler)) compiler(compiler)
            if (monitor != null) monitor(monitor)
            if (log != null) log(log)
        }
        .let { builder ->
            builder.load().primary.getDomainObject(this).let { program ->
                program.release(builder)
                LoadedProgram(program, this)
            }
        }
