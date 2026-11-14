// Writes an archive's types as the version-neutral text ghicpp bundles (ghicpp.stl.StlLayouts reads
// it): released Ghidras cannot open a .gdt written by a newer one. Arguments: archive, output file.
//
// One type per line, its members on the indented lines after it, fields separated by tabs:
//   S <path> <length>                      structure, non-packed
//     <offset> <length> <name> <type> [<bit offset> <bit size>]
//   U <path> <length>                      union
//     <length> <name> <type> [<bit offset> <bit size>]
//   E <path> <length>                      enum
//     <name> <value>
//   T <path> <type>                        typedef
//   F <path> <return type> <varargs>       function definition
//     <name> <type>
// A type is a path, then `|*<size>` for each pointer and `|[<count>]` for each array around it; `?` is
// the target of a pointer to nothing. An empty name is a member Ghidra has no name for.
// @category Data Types
// @runtime Java

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

public class ExportStlLayouts extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		FileDataTypeManager archive = FileDataTypeManager.openFileArchive(new File(args[0]), false);
		int written = 0;
		try (PrintWriter out = new PrintWriter(args[1], "UTF-8")) {
			List<DataType> types = new ArrayList<>();
			archive.getAllDataTypes(types);
			types.sort(Comparator.comparing(DataType::getPathName));
			for (DataType dt : types) {
				if (write(out, dt)) {
					written++;
				}
			}
		}
		finally {
			archive.close();
		}
		println(String.format("%s: %d types", args[1], written));
	}

	private static boolean write(PrintWriter out, DataType dt) {
		String path = dt.getPathName();
		if (dt instanceof Structure s) {
			out.println("S\t" + path + "\t" + (s.isNotYetDefined() ? 0 : s.getLength()));
			if (s.isNotYetDefined()) {
				return true;
			}
			for (DataTypeComponent m : s.getDefinedComponents()) {
				out.println("\t" + m.getOffset() + "\t" + m.getLength() + "\t" + member(m));
			}
		}
		else if (dt instanceof Union u) {
			out.println("U\t" + path + "\t" + (u.isNotYetDefined() ? 0 : u.getLength()));
			for (DataTypeComponent m : u.getComponents()) {
				out.println("\t" + m.getLength() + "\t" + member(m));
			}
		}
		else if (dt instanceof Enum e) {
			out.println("E\t" + path + "\t" + e.getLength());
			for (String name : e.getNames()) {
				out.println("\t" + name + "\t" + e.getValue(name));
			}
		}
		else if (dt instanceof TypeDef t) {
			out.println("T\t" + path + "\t" + ref(t.getDataType()));
		}
		else if (dt instanceof FunctionDefinition f) {
			out.println("F\t" + path + "\t" + ref(f.getReturnType()) + "\t" + (f.hasVarArgs() ? 1 : 0));
			for (ParameterDefinition p : f.getArguments()) {
				out.println("\t" + Objects.toString(p.getName(), "") + "\t" + ref(p.getDataType()));
			}
		}
		else {
			return false; // built-ins, pointers and arrays are written where they are used
		}
		return true;
	}

	private static String member(DataTypeComponent m) {
		String name = Objects.toString(m.getFieldName(), "");
		if (m.getDataType() instanceof BitFieldDataType b) {
			return name + "\t" + ref(b.getBaseDataType()) + "\t" + b.getBitOffset() + "\t" + b.getBitSize();
		}
		return name + "\t" + ref(m.getDataType());
	}

	private static String ref(DataType dt) {
		if (dt == null) {
			return "?";
		}
		if (dt instanceof Pointer p) {
			return ref(p.getDataType()) + "|*" + p.getLength();
		}
		if (dt instanceof Array a) {
			return ref(a.getDataType()) + "|[" + a.getNumElements() + "]";
		}
		return dt.getPathName();
	}
}
