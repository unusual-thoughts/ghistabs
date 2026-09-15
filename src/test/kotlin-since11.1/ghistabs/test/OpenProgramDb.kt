package ghistabs.test

import db.DBHandle
import ghidra.framework.data.OpenMode
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor

/** 11.1+: `OpenMode`. Upgrades are refused, so a database written by an older Ghidra throws. */
fun openProgramDb(dbh: DBHandle, consumer: Any) = ProgramDB(dbh, OpenMode.UPDATE, TaskMonitor.DUMMY, consumer)
