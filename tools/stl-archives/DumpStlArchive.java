// Writes every type in an archive as text: path, kind and size, each component's offset, size, name
// and type, each typedef's target. Two Ghidra versions that read an archive the same way write the
// same text. Arguments: archive, output file.
// @category Data Types
// @runtime Java

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class DumpStlArchive extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		FileDataTypeManager archive = FileDataTypeManager.openFileArchive(new File(args[0]), false);
		try (PrintWriter out = new PrintWriter(args[1])) {
			List<DataType> types = new ArrayList<>();
			archive.getAllDataTypes(types);
			types.sort(Comparator.comparing(DataType::getPathName));
			for (DataType dt : types) {
				if (dt instanceof Pointer || dt instanceof Array) {
					continue;
				}
				out.println(dt.getPathName() + " " + dt.getClass().getSimpleName().replace("DB", "") +
					" " + dt.getLength());
				if (dt instanceof Composite) {
					for (DataTypeComponent m : ((Composite) dt).getDefinedComponents()) {
						out.println("  +" + m.getOffset() + " " + m.getLength() + " " + m.getFieldName() +
							" " + m.getDataType().getPathName());
					}
				}
				else if (dt instanceof TypeDef) {
					out.println("  = " + ((TypeDef) dt).getDataType().getPathName());
				}
			}
			println(String.format("%s: %d types", args[0], types.size()));
		}
		finally {
			archive.close();
		}
	}
}
