package ghistabs.test

import db.DBConstants
import db.DBHandle
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor

/** Pre-11.1: the open mode is `DBConstants`' int, which 11.1 replaced with `OpenMode`. */
fun openProgramDb(dbh: DBHandle, consumer: Any) = ProgramDB(dbh, DBConstants.UPDATE, TaskMonitor.DUMMY, consumer)
