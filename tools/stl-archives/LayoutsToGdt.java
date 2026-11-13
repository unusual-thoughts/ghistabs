// Builds a .gdt from the layouts text ExportStlLayouts writes (its header describes the format), on
// whichever Ghidra runs it: CI runs it on the oldest release ghicpp supports, whose archives every newer
// release opens, where an archive written by a newer Ghidra opens nowhere older. Arguments: layouts
// text, output .gdt.
// @category Data Types
// @runtime Java

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class LayoutsToGdt extends GhidraScript {

	private static class Record {
		final char kind;
		final String[] fields;
		final List<String[]> members = new ArrayList<>();

		Record(char kind, String[] fields) {
			this.kind = kind;
			this.fields = fields;
		}
	}

	private final Map<String, Record> records = new LinkedHashMap<>();
	private final Map<String, DataType> built = new HashMap<>();
	private final Set<String> filled = new HashSet<>();
	private final Map<String, DataType> builtins = new HashMap<>();

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		parse(new String(Files.readAllBytes(new File(args[0]).toPath()), StandardCharsets.UTF_8));
		for (DataType dt : new DataType[] { BooleanDataType.dataType, CharDataType.dataType,
			SignedCharDataType.dataType, UnsignedCharDataType.dataType, ShortDataType.dataType,
			UnsignedShortDataType.dataType, IntegerDataType.dataType, UnsignedIntegerDataType.dataType,
			LongDataType.dataType, UnsignedLongDataType.dataType, LongLongDataType.dataType,
			UnsignedLongLongDataType.dataType, FloatDataType.dataType, DoubleDataType.dataType,
			LongDoubleDataType.dataType, WideCharDataType.dataType, WideChar16DataType.dataType,
			WideChar32DataType.dataType, VoidDataType.dataType, ByteDataType.dataType,
			SignedByteDataType.dataType, Undefined1DataType.dataType, Undefined2DataType.dataType,
			Undefined4DataType.dataType, Undefined8DataType.dataType, DataType.DEFAULT }) {
			builtins.put(dt.getPathName(), dt);
		}

		File out = new File(args[1]);
		out.delete();
		FileDataTypeManager gdt = FileDataTypeManager.createFileArchive(out);
		try {
			int tx = gdt.startTransaction("layouts");
			try {
				for (String path : records.keySet()) {
					gdt.resolve(type(path), DataTypeConflictHandler.DEFAULT_HANDLER);
				}
			}
			finally {
				gdt.endTransaction(tx, true);
			}
			gdt.save();
			println(String.format("%s: %d types", args[1], records.size()));
		}
		finally {
			gdt.close();
		}
	}

	private void parse(String text) {
		Record current = null;
		for (String line : text.split("\n")) {
			if (line.isEmpty()) {
				continue;
			}
			String[] fields = line.split("\t", -1);
			if (line.startsWith("\t")) {
				current.members.add(Arrays.copyOfRange(fields, 1, fields.length));
			}
			else {
				current = new Record(fields[0].charAt(0), Arrays.copyOfRange(fields, 1, fields.length));
				records.put(current.fields[0], current);
			}
		}
	}

	private DataType type(String path) {
		DataType done = built.get(path);
		if (done != null) {
			fill(path, done);
			return done;
		}
		Record record = records.get(path);
		if (record == null) {
			DataType builtin = builtins.get(path);
			if (builtin == null) {
				throw new IllegalArgumentException("no type " + path);
			}
			return builtin;
		}
		CategoryPath at = new CategoryPath(path);
		DataType made;
		switch (record.kind) {
			case 'S':
				made = new StructureDataType(at.getParent(), at.getName(),
					Integer.parseInt(record.fields[1]));
				break;
			case 'U':
				made = new UnionDataType(at.getParent(), at.getName());
				break;
			case 'E': {
				EnumDataType e =
					new EnumDataType(at.getParent(), at.getName(), Integer.parseInt(record.fields[1]));
				for (String[] m : record.members) {
					e.add(m[0], Long.parseLong(m[1]));
				}
				made = e;
				break;
			}
			case 'T':
				made = new TypedefDataType(at.getParent(), at.getName(), ref(record.fields[1]));
				break;
			case 'F': {
				FunctionDefinitionDataType f = new FunctionDefinitionDataType(at.getParent(), at.getName());
				built.put(path, f);
				f.setReturnType(ref(record.fields[1]));
				f.setVarArgs(record.fields[2].equals("1"));
				ParameterDefinition[] params = new ParameterDefinition[record.members.size()];
				for (int i = 0; i < params.length; i++) {
					String[] m = record.members.get(i);
					params[i] = new ParameterDefinitionImpl(m[0].isEmpty() ? null : m[0], ref(m[1]), null);
				}
				f.setArguments(params);
				made = f;
				break;
			}
			default:
				throw new IllegalArgumentException("unknown record " + record.kind + " for " + path);
		}
		built.put(path, made);
		fill(path, made);
		return made;
	}

	private void fill(String path, DataType dt) {
		if (!(dt instanceof Composite) || !filled.add(path)) {
			return;
		}
		for (String[] m : records.get(path).members) {
			if (dt instanceof Structure) {
				Structure s = (Structure) dt;
				int offset = Integer.parseInt(m[0]);
				int length = Integer.parseInt(m[1]);
				String name = m[2].isEmpty() ? null : m[2];
				DataType type = ref(m[3]);
				try {
					if (m.length == 6) {
						s.insertBitFieldAt(offset, length, Integer.parseInt(m[4]), type,
							Integer.parseInt(m[5]), name, null);
					}
					else if (length > 0) {
						s.replaceAtOffset(offset, type, length, name, null);
					}
				}
				catch (InvalidDataTypeException e) {
					throw new IllegalStateException(path + " +" + offset, e);
				}
			}
			else {
				Union u = (Union) dt;
				String name = m[1].isEmpty() ? null : m[1];
				DataType type = ref(m[2]);
				try {
					if (m.length == 5) {
						u.addBitField(type, Integer.parseInt(m[4]), name, null);
					}
					else {
						u.add(type, Integer.parseInt(m[0]), name, null);
					}
				}
				catch (InvalidDataTypeException e) {
					throw new IllegalStateException(path, e);
				}
			}
		}
	}

	private DataType ref(String spec) {
		String[] parts = spec.split("\\|");
		DataType dt = parts[0].equals("?") ? null : type(parts[0]);
		for (int i = 1; i < parts.length; i++) {
			String wrap = parts[i];
			if (wrap.startsWith("*")) {
				dt = new PointerDataType(dt, Integer.parseInt(wrap.substring(1)));
			}
			else if (wrap.startsWith("[")) {
				int count = Integer.parseInt(wrap.substring(1, wrap.length() - 1));
				dt = new ArrayDataType(dt, count, dt.getLength());
			}
			else {
				throw new IllegalArgumentException("bad type " + spec);
			}
		}
		return dt;
	}
}
