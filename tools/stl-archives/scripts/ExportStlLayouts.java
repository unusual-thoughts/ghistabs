// Writes an archive's types as the version-neutral text ghicpp bundles (ghicpp.stl.StlLayouts reads
// it): released Ghidras cannot open a .gdt written by a newer one. Arguments: archive (or `-` for the
// program's own types), output file.
//
// An archive made for one architecture starts with it:
//   A <language id> <compiler spec id>
// Then one type per line, its members on the indented lines after it, fields separated by tabs:
//   S <path> <length>                      structure, non-packed
//     <offset> <length> <name> <type> [<bit offset> <bit size>]
//   U <path> <length>                      union
//     <length> <name> <type> [<bit offset> <bit size>]
//   E <path> <length>                      enum
//     <name> <value>
//   T <path> <type>                        typedef
//   B <path> <length> <signed>             built-in integer, of the Ghidra that wrote it
//   F <path> <return type> <varargs>       function definition
//     <name> <type>
// A type is a path, then `|*<size>` for each pointer and `|[<count>]` for each array around it; `?` is
// the target of a pointer to nothing. The wraps are read off the end, since a path may hold `|` itself.
// An empty name is a member Ghidra has no name for.
// @category Data Types
// @runtime Java

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.ProgramArchitecture;

public class ExportStlLayouts extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		// `-` writes the program's own types, as GccStlArchiveScript leaves them.
		boolean own = args[0].equals("-");
		DataTypeManager archive = own ? currentProgram.getDataTypeManager()
				: FileDataTypeManager.openFileArchive(new File(args[0]), false);
		int written = 0;
		try (PrintWriter out = new PrintWriter(args[1], "UTF-8")) {
			ProgramArchitecture arch = archive.getProgramArchitecture();
			if (arch != null) {
				out.println("A\t" + arch.getLanguage().getLanguageID() + "\t" +
					arch.getCompilerSpec().getCompilerSpecID());
			}
			List<DataType> types = new ArrayList<>();
			archive.getAllDataTypes(types);
			types.sort(Comparator.comparing(DataType::getPathName));
			Set<String> seen = new HashSet<>();
			for (DataType dt : types) {
				// A program's getAllDataTypes lists some of its types twice, and some it has deleted.
				if (!dt.isDeleted() && seen.add(dt.getPathName()) && write(out, dt)) {
					written++;
				}
			}
		}
		finally {
			if (!own) {
				archive.close();
			}
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
			// A shifted pointer (`char * __((offset(0xc)))`) carries its offset.
			ComponentOffsetSettingsDefinition shift = ComponentOffsetSettingsDefinition.DEF;
			long offset = shift.hasValue(t.getDefaultSettings()) ? shift.getValue(t.getDefaultSettings()) : 0;
			out.println("T\t" + path + "\t" + ref(t.getDataType()) + (offset != 0 ? "\t" + offset : ""));
		}
		else if (dt instanceof FunctionDefinition f) {
			out.println("F\t" + path + "\t" + ref(f.getReturnType()) + "\t" + (f.hasVarArgs() ? 1 : 0));
			for (ParameterDefinition p : f.getArguments()) {
				out.println("\t" + Objects.toString(p.getName(), "") + "\t" + ref(p.getDataType()));
			}
		}
		else if (dt instanceof BuiltInDataType && dt instanceof AbstractIntegerDataType i) {
			// Some (intptr_t) are newer than the Ghidra the text is read back on, which makes them of their size.
			out.println("B\t" + path + "\t" + i.getLength() + "\t" + (i.isSigned() ? 1 : 0));
		}
		else {
			return false; // other built-ins, pointers and arrays are written where they are used
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
