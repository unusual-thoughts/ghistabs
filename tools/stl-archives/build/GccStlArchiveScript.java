// Builds a data type archive of the libstdc++ types a program's DWARF defines, filed where Ghidra's GNU
// demangler expects them, so the `this` of a demangled `std::` method lands on the real layout instead of
// an empty placeholder: the GNU counterpart of MsvcStlArchiveScript.
//
// Run it on the probe (tools/stl-archives/stl_probe.cpp built with g++ -g), imported without analysis:
// the script reads its DWARF itself. Its argument is the .gdt to write; without one it asks.
//
// Beside the archive it writes the classes' bases, with access and virtuality, and the virtual functions
// each introduces, as `<archive>.classes.xml.gz` (ghicpp.stl.StdClasses), so this needs the ghicpp
// extension installed.
// @category Data Types
// @runtime Java

import java.io.File;
import java.util.*;

import ghicpp.Access;
import ghicpp.stl.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId;
import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.GnuDemangler;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;

public class GccStlArchiveScript extends GhidraScript {

	/** The namespaces whose types the archive is for; what they depend on comes along. */
	private static final Set<String> ROOTS = StlApplier.GNU_ROOTS;

	private final GnuDemangler demangler = new GnuDemangler();

	private int pointerSize;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File out = args.length > 0 ? new File(args[0]) : askFile("Archive to lay out", "Write");
		String name = out.getName().replaceAll("\\.gdt$", "");
		File classesFile = new File(out.getAbsoluteFile().getParentFile(), name + StdClasses.SUFFIX);
		classesFile.getParentFile().mkdirs();
		pointerSize = currentProgram.getDefaultPointerSize();

		DWARFImportOptions options = new DWARFImportOptions();
		options.setOrganizeTypesBySourceFile(false);
		options.setImportFuncs(false);
		try (DWARFProgram dwarf = new DWARFProgram(currentProgram, options, monitor)) {
			dwarf.init(monitor);
			DWARFDataTypeManager dwarfTypes = dwarf.getDwarfDTM();
			dwarfTypes.importAllDataTypes(monitor);
			Read read = readClasses(dwarf, dwarfTypes);
			build(name, classesFile, read);
		}
	}

	/** The classes' bases and slots, off the DWARF, by their path in the archive. */
	private record Read(StdClasses classes, Map<String, DataType> slotTypes, Map<String, DataType> types,
			Set<String> abiTagged) {
		DataType typeOf(StdClass cls, StdSlot slot) {
			return slotTypes.get(cls.getPath() + "@" + slot.getOffset());
		}

		/** Where the class read at [path] is now: renamed, or folded into the copy of the name it had. */
		String now(String path) {
			DataType dt = types.get(path);
			return dt != null && !dt.isDeleted() ? dt.getPathName() : CONFLICT.matcher(path).replaceFirst("");
		}

		/** The classes at the paths their types are at now. */
		StdClasses moved() {
			List<StdClass> out = new ArrayList<>();
			for (StdClass c : classes.getClasses()) {
				List<StdBase> bases = new ArrayList<>();
				for (StdBase b : c.getBases()) {
					bases.add(new StdBase(now(b.getPath()), b.getAccess(), b.isVirtual(), b.getOffset()));
				}
				out.add(new StdClass(now(c.getPath()), bases, c.getSlots()));
			}
			return new StdClasses(out);
		}
	}

	/**
	 * Lays the library's types out in the probe's own data type manager, which has the probe's data
	 * organization (the sizes of `long`, `size_t` and the pointers), for ExportStlLayouts to write out:
	 * 12.3 cannot make a .gdt for an architecture from a script (it flushes its events under the
	 * archive's lock), and LayoutsToGdt builds the shipped archive on 10.4 anyway.
	 */
	private void build(String name, File classesFile, Read read) throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		int moved = refile(dtm);
		int vfptrs = nameVfptrs(dtm);
		int dropped = StlArchiveTypes.prune(dtm, ROOTS, monitor);
		int selfBases = StlSelfBases.apply(dtm, read.classes().getClasses(), pointerSize);
		StlShape.Result shape = StlShape.apply(dtm, read.classes().getClasses(), pointerSize, read::typeOf);
		// The slots' function types, which the vftables brought in.
		refile(dtm);
		int typedefs = addTypedefs(dtm);
		// Last, as laying the classes brings the built-ins back.
		portableBuiltins(dtm);
		int folded = foldConflicts(dtm);
		tagAbi(dtm, read);
		int methods = checkAgainstMethods(dtm);
		println(String.format(
			"%s: %d std types filed at their demangled paths, %d unrelated types dropped, " +
				"%d typedefs, %d vfptrs named, %d bases laid as their non-virtual part, %d bases named, " +
				"%d own vftables, " +
				"%d classes split around one; %d method classes resolve to an archive type; " +
				"%d classes with bases; %d copies folded",
			name, moved, dropped, typedefs, vfptrs, selfBases, shape.getBases(), shape.getVftables(), shape.getSplit(),
			methods, read.classes().getClasses().stream().filter(c -> !c.getBases().isEmpty()).count(), folded));
		read.moved().write(classesFile);
	}

	/**
	 * Files every type the DWARF importer filed under `/DWARF` at the same path off the root, which is
	 * where the demangler files a class: `/DWARF/_UNCATEGORIZED_/std/vector<int,_std::allocator<int>_>`
	 * becomes `/std/vector<…>`. Returns how many of the library's it filed.
	 */
	private int refile(DataTypeManager dtm) throws Exception {
		int moved = 0;
		List<DataType> types = new ArrayList<>();
		dtm.getAllDataTypes(types);
		for (DataType dt : types) {
			monitor.checkCancelled();
			List<String> rest = underDwarf(dt.getCategoryPath());
			if (rest == null || dt instanceof FunctionDefinition && (rest.isEmpty() || !ROOTS.contains(rest.get(0)))) {
				continue;
			}
			CategoryPath target = rest.isEmpty() ? CategoryPath.ROOT : new CategoryPath(CategoryPath.ROOT, rest);
			try {
				dt.setCategoryPath(target);
			}
			catch (Exception e) {
				printerr("cannot move " + dt.getPathName() + ": " + e.getMessage());
				continue;
			}
			if (!rest.isEmpty() && ROOTS.contains(rest.get(0))) {
				moved++;
			}
		}
		dedupe(dtm);
		return moved;
	}

	/**
	 * Leaves one type at each path: the importer files a type each compile unit defines once per unit
	 * where they agree, and Ghidra lets a category hold two of one name. A copy that agrees with the first
	 * is replaced by it, one that does not is kept apart as `.conflict<n>`.
	 */
	private void dedupe(DataTypeManager dtm) throws Exception {
		List<DataType> types = new ArrayList<>();
		dtm.getAllDataTypes(types);
		Map<String, DataType> first = new HashMap<>();
		for (DataType dt : types) {
			if (dt.isDeleted()) {
				continue;
			}
			DataType kept = first.putIfAbsent(dt.getPathName(), dt);
			// getAllDataTypes lists some of a program's types twice.
			if (kept == null || kept == dt || dtm.getID(kept) == dtm.getID(dt)) {
				continue;
			}
			if (kept.isEquivalent(dt)) {
				dtm.replaceDataType(dt, kept, false);
				continue;
			}
			int n = 1;
			while (first.containsKey(dt.getCategoryPath().getPath() + "/" + dt.getName() + ".conflict" + n) ||
				dtm.getDataType(dt.getCategoryPath(), dt.getName() + ".conflict" + n) != null) {
				n++;
			}
			dt.setName(dt.getName() + ".conflict" + n);
			first.put(dt.getPathName(), dt);
		}
	}

	private static final java.util.regex.Pattern CONFLICT = java.util.regex.Pattern.compile("\\.conflict\\d*$");

	/**
	 * Folds each `X.conflict<n>` into the `X` beside it when the two lay out alike, and names the rest
	 * `X#<n>`, numbered in path order. The copies come from the probe's units: the COW unit's
	 * `std::__cow_string` is a typedef of `std::basic_string<char>` where the others define a struct of the
	 * same pointer, and the classes holding one differ only in that. Ghidra's resolve folds or renumbers a
	 * `.conflict` name as it pleases, so none is left for 10.4 to read back differently.
	 */
	private int foldConflicts(DataTypeManager dtm) throws Exception {
		List<DataType> types = new ArrayList<>();
		dtm.getAllDataTypes(types);
		types.sort(Comparator.comparing(DataType::getPathName));
		int folded = 0;
		Map<String, Integer> next = new HashMap<>();
		Set<DataType> seen = Collections.newSetFromMap(new IdentityHashMap<>());
		for (DataType dt : types) {
			monitor.checkCancelled();
			// getAllDataTypes lists some types twice, and some it has deleted.
			if (dt.isDeleted() || !seen.add(dt)) {
				continue;
			}
			java.util.regex.Matcher m = CONFLICT.matcher(dt.getName());
			if (!m.find()) {
				continue;
			}
			String base = dt.getName().substring(0, m.start());
			DataType original = dtm.getDataType(dt.getCategoryPath(), base);
			if (original != null && alike(original, dt, 0)) {
				dtm.replaceDataType(dt, original, false);
				folded++;
				continue;
			}
			String key = dt.getCategoryPath().getPath() + "/" + base;
			int n = next.getOrDefault(key, 1);
			while (dtm.getDataType(dt.getCategoryPath(), base + "#" + n) != null) {
				n++;
			}
			next.put(key, n + 1);
			dt.setName(base + "#" + n);
		}
		return folded;
	}

	/**
	 * Whether two types lay out alike: the same size, kind and fields at the same offsets, looking through
	 * typedefs and conflict names, and taking any two pointers of one size as alike.
	 */
	private static boolean alike(DataType a, DataType b, int depth) {
		if (a == b || a.isEquivalent(b)) {
			return true;
		}
		while (a instanceof TypeDef t) {
			a = t.getBaseDataType();
		}
		while (b instanceof TypeDef t) {
			b = t.getBaseDataType();
		}
		if (a.getLength() != b.getLength() || depth > 8) {
			return a.getLength() == b.getLength();
		}
		if (a instanceof Pointer && b instanceof Pointer) {
			return true;
		}
		if (a instanceof Array x && b instanceof Array y) {
			return x.getNumElements() == y.getNumElements() && alike(x.getDataType(), y.getDataType(), depth + 1);
		}
		if (a instanceof FunctionDefinition x && b instanceof FunctionDefinition y) {
			ParameterDefinition[] p = x.getArguments(), q = y.getArguments();
			if (p.length != q.length || x.hasVarArgs() != y.hasVarArgs() ||
				!alike(x.getReturnType(), y.getReturnType(), depth + 1)) {
				return false;
			}
			for (int i = 0; i < p.length; i++) {
				if (!alike(p[i].getDataType(), q[i].getDataType(), depth + 1)) {
					return false;
				}
			}
			return true;
		}
		if (a instanceof Composite x && b instanceof Composite y && sameFields(x, y, depth)) {
			return true;
		}
		// A wrapper, `std::__cow_string`'s union of a `std::string` and its bytes, is alike what it wraps.
		return wraps(a, b, depth) || wraps(b, a, depth) ||
			!(a instanceof Composite) && !(b instanceof Composite) && a.getClass() == b.getClass();
	}

	private static boolean sameFields(Composite x, Composite y, int depth) {
		if ((x instanceof Union) != (y instanceof Union)) {
			return false;
		}
		DataTypeComponent[] p = x.getDefinedComponents(), q = y.getDefinedComponents();
		if (p.length != q.length) {
			return false;
		}
		for (int i = 0; i < p.length; i++) {
			if (p[i].getOffset() != q[i].getOffset() || p[i].getLength() != q[i].getLength() ||
				!Objects.equals(p[i].getFieldName(), q[i].getFieldName()) ||
				!alike(p[i].getDataType(), q[i].getDataType(), depth + 1)) {
				return false;
			}
		}
		return true;
	}

	/** Whether [outer] is a struct of one field, or a union with a member, that spans it and is alike [inner]. */
	private static boolean wraps(DataType outer, DataType inner, int depth) {
		if (!(outer instanceof Composite c) || c instanceof Structure && c.getNumDefinedComponents() != 1) {
			return false;
		}
		for (DataTypeComponent m : c.getDefinedComponents()) {
			if (m.getOffset() == 0 && m.getLength() == outer.getLength() && alike(m.getDataType(), inner, depth + 1)) {
				return true;
			}
		}
		return false;
	}

	/** The built-in integers newer than Ghidra 10.4, which the DWARF importer takes `<stdint.h>`'s typedefs as. */
	private static final List<String> NEWER_BUILTINS = List.of("intptr_t", "uintptr_t", "int8_t", "int16_t",
		"int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t");

	/**
	 * Makes the built-ins newer than Ghidra 10.4 typedefs of the integer of their size, so the layouts text
	 * reads back the same on 10.4.
	 */
	private void portableBuiltins(DataTypeManager dtm) throws Exception {
		for (String name : NEWER_BUILTINS) {
			DataType builtin = dtm.getDataType(new DataTypePath(CategoryPath.ROOT, name));
			if (!(builtin instanceof BuiltInDataType) || !(builtin instanceof AbstractIntegerDataType i)) {
				continue;
			}
			DataType sized = i.isSigned() ? AbstractIntegerDataType.getSignedDataType(i.getLength(), dtm)
					: AbstractIntegerDataType.getUnsignedDataType(i.getLength(), dtm);
			dtm.replaceDataType(builtin, new TypedefDataType(CategoryPath.ROOT, name, sized, dtm), true);
		}
	}

	/** gcc names a class's vptr `_vptr.<Class>`; ghicpp and Ghidra's class tools name it `vfptr`. */
	private int nameVfptrs(DataTypeManager dtm) {
		int named = 0;
		Iterator<Structure> it = dtm.getAllStructures();
		while (it.hasNext()) {
			Structure s = it.next();
			for (DataTypeComponent c : s.getDefinedComponents()) {
				String name = c.getFieldName();
				if (name != null && name.startsWith("_vptr")) {
					DataType target = c.getDataType() instanceof Pointer p ? p.getDataType() : null;
					s.replaceAtOffset(c.getOffset(), new PointerDataType(target, pointerSize, dtm), pointerSize,
						"vfptr", c.getComment());
					named++;
				}
			}
		}
		return named;
	}

	// ---- the classes, off the DWARF ----

	private Read readClasses(DWARFProgram dwarf, DWARFDataTypeManager dwarfTypes) throws Exception {
		Map<String, StdClass> classes = new TreeMap<>();
		Map<String, DataType> slotTypes = new HashMap<>();
		Map<Long, DIEAggregate> byOffset = new HashMap<>();
		Map<String, DIEAggregate> byPath = new HashMap<>();
		Map<String, DataType> types = new HashMap<>();
		Set<String> abiTagged = new HashSet<>();
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		for (DIEAggregate die : dwarf.allAggregates()) {
			monitor.checkCancelled();
			if (!die.getTag().isStructureType() || die.getTag() == DWARFTag.DW_TAG_union_type ||
				die.getBool(DWARFAttributeId.DW_AT_declaration, false)) {
				continue;
			}
			String path = archivePath(dwarfTypes, die);
			if (path == null) {
				continue;
			}
			byOffset.put(die.getOffset(), die);
			if (byPath.putIfAbsent(path, die) == null) {
				types.put(path, dtm.getDataType(dwarfTypes.getDataType(die, null).getDataTypePath()));
				if (abiTagged(die)) {
					abiTagged.add(path);
				}
			}
		}
		for (Map.Entry<String, DIEAggregate> e : byPath.entrySet()) {
			String path = e.getKey();
			DIEAggregate die = e.getValue();
			List<StdBase> bases = new ArrayList<>();
			for (DebugInfoEntry child : die.getChildren(DWARFTag.DW_TAG_inheritance)) {
				DIEAggregate inh = dwarf.getDIEContainer().getAggregate(child);
				DIEAggregate base = definition(dwarf, inh.getTypeRef());
				String basePath = base == null ? null : archivePath(dwarfTypes, base);
				if (basePath == null) {
					continue;
				}
				boolean virtual = inh.getUnsignedLong(DWARFAttributeId.DW_AT_virtuality, 0) != 0;
				Long offset = virtual ? null
						: (long) inh.parseDataMemberOffset(DWARFAttributeId.DW_AT_data_member_location, 0);
				bases.add(new StdBase(basePath, access(inh, die), virtual, offset));
			}
			classes.put(path, new StdClass(path, bases, List.of()));
		}
		// The slots each class introduces: those past its primary base's table.
		Map<String, Table> tables = new HashMap<>();
		for (String path : byPath.keySet()) {
			StdClass cls = classes.get(path);
			List<StdSlot> slots = new ArrayList<>();
			for (Entry entry : table(path, classes, byPath, dwarf, tables).introduced()) {
				StdSlot slot = new StdSlot((long) entry.index() * pointerSize, entry.name());
				slots.add(slot);
				FunctionDefinition type = dwarfTypes.getFunctionSignature(entry.fn());
				if (type != null) {
					slotTypes.put(path + "@" + slot.getOffset(), type);
				}
			}
			if (!slots.isEmpty()) {
				classes.put(path, new StdClass(path, cls.getBases(), slots));
			}
		}
		return new Read(new StdClasses(new ArrayList<>(classes.values())), slotTypes, types, abiTagged);
	}

	/**
	 * Whether the class is the C++11 ABI's of a name both ABIs define, which its members' mangled names tag
	 * `B5cxx11` (`std::ios_base::failure[abi:cxx11]`): DWARF names the two alike.
	 */
	private static boolean abiTagged(DIEAggregate die) {
		String name = die.getName();
		if (name == null) {
			return false;
		}
		String tagged = name.length() + name + "B5cxx11";
		for (DebugInfoEntry child : die.getHeadFragment().getChildren()) {
			if (child.getTag() != DWARFTag.DW_TAG_subprogram) {
				continue;
			}
			DIEAggregate fn = die.getProgram().getDIEContainer().getAggregate(child);
			String linkage = fn == null ? null : fn.getString(DWARFAttributeId.DW_AT_linkage_name, null);
			if (linkage != null && linkage.contains(tagged)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Names each class the C++11 ABI tags as the demangler does, `failure[abi:cxx11]`, and gives the
	 * untagged name back to the other ABI's copy.
	 */
	private void tagAbi(DataTypeManager dtm, Read read) throws Exception {
		for (String path : read.abiTagged()) {
			DataType dt = read.types().get(path);
			if (dt == null || dt.isDeleted()) {
				continue;
			}
			String base = dt.getName().replaceFirst("#\\d+$", "");
			dt.setName(base + "[abi:cxx11]");
			DataType other = dtm.getDataType(dt.getCategoryPath(), base + "#1");
			if (other != null && dtm.getDataType(dt.getCategoryPath(), base) == null &&
				dtm.getDataType(dt.getCategoryPath(), base + "#2") == null) {
				other.setName(base);
			}
		}
	}

	/** A class's vtable: how many entries, whether one is a virtual destructor, and those it introduces. */
	private record Table(int size, boolean virtualDtor, List<Entry> introduced) {
		static final Table NONE = new Table(0, false, List.of());
	}

	/** A vtable entry a class introduces, at [index], for the virtual function [fn]. */
	private record Entry(int index, String name, DIEAggregate fn) {}

	/**
	 * [path]'s vtable: its primary base's entries (the first non-virtual base at offset 0 with a vtable),
	 * then those it introduces. gcc records each virtual function's index, but a destructor's: the Itanium
	 * ABI gives a virtual destructor two entries (complete and deleting) where it is declared, which a class
	 * whose primary base has none introduces in the first gap its other entries leave.
	 */
	private Table table(String path, Map<String, StdClass> classes, Map<String, DIEAggregate> byPath,
			DWARFProgram dwarf, Map<String, Table> memo) {
		Table known = memo.get(path);
		if (known != null) {
			return known;
		}
		memo.put(path, Table.NONE);
		StdClass cls = classes.get(path);
		DIEAggregate die = byPath.get(path);
		if (cls == null || die == null) {
			return Table.NONE;
		}
		Table primary = Table.NONE;
		for (StdBase base : cls.getBases()) {
			if (!base.isVirtual() && Objects.equals(base.getOffset(), 0L)) {
				Table t = table(base.getPath(), classes, byPath, dwarf, memo);
				if (t.size() > 0) {
					primary = t;
					break;
				}
			}
		}
		List<Entry> entries = new ArrayList<>();
		DIEAggregate dtor = null;
		for (DebugInfoEntry child : die.getChildren(DWARFTag.DW_TAG_subprogram)) {
			DIEAggregate fn = dwarf.getDIEContainer().getAggregate(child);
			if (fn.getUnsignedLong(DWARFAttributeId.DW_AT_virtuality, 0) == 0) {
				continue;
			}
			long index = vtableIndex(fn);
			String name = fn.getName();
			if (index >= primary.size()) {
				entries.add(new Entry((int) index, name, fn));
			}
			else if (index < 0 && name != null && name.startsWith("~")) {
				dtor = fn;
			}
		}
		int size = primary.size();
		for (Entry entry : entries) {
			size = Math.max(size, entry.index() + 1);
		}
		if (dtor != null && !primary.virtualDtor()) {
			Set<Integer> taken = new HashSet<>();
			entries.forEach(entry -> taken.add(entry.index()));
			int at = primary.size();
			while (taken.contains(at) || taken.contains(at + 1)) {
				at++;
			}
			entries.add(new Entry(at, dtor.getName(), dtor));
			entries.add(new Entry(at + 1, dtor.getName(), dtor));
			size = Math.max(size, at + 2);
		}
		entries.sort(Comparator.comparingInt(Entry::index));
		Table table = new Table(size, primary.virtualDtor() || dtor != null, entries);
		memo.put(path, table);
		return table;
	}

	/** A virtual function's index in its class's vtable, or -1 for one that is not virtual. */
	private static long vtableIndex(DIEAggregate fn) {
		if (!fn.hasAttribute(DWARFAttributeId.DW_AT_vtable_elem_location)) {
			return -1;
		}
		try {
			return fn.parseUnsignedLong(DWARFAttributeId.DW_AT_vtable_elem_location, -1);
		}
		catch (Exception e) {
			return -1;
		}
	}

	/** The definition of a class [die] may only declare. */
	private static DIEAggregate definition(DWARFProgram dwarf, DIEAggregate die) {
		if (die == null) {
			return null;
		}
		// typedefs and cv-qualifiers stand between an inheritance entry and its class in some builds.
		while (die != null && !die.getTag().isStructureType()) {
			die = die.getTypeRef();
		}
		return die;
	}

	/** DWARF's default for an inheritance entry is private in a class, public in a struct. */
	private static Access access(DIEAggregate inh, DIEAggregate owner) {
		long value = inh.getUnsignedLong(DWARFAttributeId.DW_AT_accessibility, 0);
		if (value == 0) {
			return owner.getTag() == DWARFTag.DW_TAG_class_type ? Access.PRIVATE : Access.PUBLIC;
		}
		return switch ((int) value) {
			case 1 -> Access.PUBLIC;
			case 2 -> Access.PROTECTED;
			default -> Access.PRIVATE;
		};
	}

	/** Where the archive files the type the DWARF importer made of [die]; null outside the library. */
	private static String archivePath(DWARFDataTypeManager dwarfTypes, DIEAggregate die) {
		DataType dt = dwarfTypes.getDataType(die, null);
		if (dt == null) {
			return null;
		}
		List<String> path = underDwarf(dt.getCategoryPath());
		if (path == null || path.isEmpty() || !ROOTS.contains(path.get(0))) {
			return null;
		}
		return new DataTypePath(new CategoryPath(CategoryPath.ROOT, path), dt.getName()).getPath();
	}

	/**
	 * [category]'s scopes below where the DWARF importer files types: `/DWARF/_UNCATEGORIZED_` for those
	 * with no source file, as gcc's are, else `/DWARF`; null outside both.
	 */
	private static List<String> underDwarf(CategoryPath category) {
		for (CategoryPath root : List.of(DWARFProgram.UNCAT_CATPATH, DWARFProgram.DWARF_ROOT_CATPATH)) {
			if (category.isAncestorOrSelf(root)) {
				return relative(root, category);
			}
		}
		return null;
	}

	private static List<String> relative(CategoryPath base, CategoryPath path) {
		List<String> all = path.asList();
		return all.subList(base.asList().size(), all.size());
	}

	// ---- the names the demangler gives ----

	/**
	 * The names Ghidra's GNU demangler puts in place of a library template (its standard replacements,
	 * since 11.4), each a typedef of the class, in std and in the C++11 ABI's std::__cxx11 where it has one.
	 * The demangler's `std::string` is the copy-on-write `std::basic_string<char>`, but each unit's DWARF
	 * files a `std::string` of its own ABI's: a field the C++11 unit typed `std::string` takes
	 * `std::__cxx11::string` instead, which names the same class.
	 */
	private int addTypedefs(DataTypeManager dtm) throws Exception {
		List<CategoryPath> categories = List.of(new CategoryPath("/std"), new CategoryPath("/std/__cxx11"));
		Map<String, TypeDef> made = new HashMap<>();
		for (CategoryPath category : categories) {
			for (Map.Entry<String, String> e : StlApplier.gnuAliases().entrySet()) {
				if (dtm.getDataType(category, e.getValue()) instanceof Composite target) {
					DataType t = dtm.addDataType(new TypedefDataType(category, e.getKey() + ".stl", target, dtm),
						DataTypeConflictHandler.DEFAULT_HANDLER);
					made.put(category.getPath() + "/" + e.getKey(), (TypeDef) t);
				}
			}
		}
		// The units' own, each in favor of the one of its class.
		for (CategoryPath category : categories) {
			Category cat = dtm.getCategory(category);
			if (cat == null) {
				continue;
			}
			for (DataType dt : cat.getDataTypes()) {
				String alias = CONFLICT.matcher(dt.getName()).replaceFirst("");
				if (!(dt instanceof TypeDef t) || made.containsValue(t) ||
					!StlApplier.gnuAliases().containsKey(alias)) {
					continue;
				}
				TypeDef own = made.get(t.getBaseDataType().getCategoryPath().getPath() + "/" + alias);
				if (own != null && own.getBaseDataType().isEquivalent(t.getBaseDataType())) {
					dtm.replaceDataType(t, own, false);
				}
			}
		}
		for (Map.Entry<String, TypeDef> e : made.entrySet()) {
			e.getValue().setName(e.getValue().getName().replaceFirst("\\.stl$", ""));
		}
		return made.size();
	}

	/**
	 * How many distinct classes the probe's own member functions demangle into resolve to an archive
	 * type: the classes Ghidra will make `this` types of, so a low count means the spellings disagree.
	 */
	private int checkAgainstMethods(DataTypeManager dtm) {
		Set<String> seen = new TreeSet<>();
		Set<String> missing = new TreeSet<>();
		StlIndex index = new StlIndex(dtm);
		for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(false)) {
			// An x86 PE's symbols carry a leading `_`.
			String name = sym.getName().startsWith("__ZN") ? sym.getName().substring(1) : sym.getName();
			if (!name.startsWith("_ZN")) {
				continue;
			}
			DemangledObject demangled;
			try {
				demangled = demangler.demangle(
					demangler.createMangledContext(name, demangler.createDefaultOptions(), null, null));
			}
			catch (DemangledException | RuntimeException e) {
				continue;
			}
			if (!(demangled instanceof DemangledFunction fn) || fn.getNamespace() == null) {
				continue;
			}
			Demangled owner = fn.getNamespace();
			if (owner.getNamespace() == null) {
				continue;
			}
			LinkedList<String> path = new LinkedList<>();
			for (Demangled ns = owner.getNamespace(); ns != null; ns = ns.getNamespace()) {
				path.addFirst(SymbolUtilities.replaceInvalidChars(ns.getName(), true));
			}
			if (!ROOTS.contains(path.get(0))) {
				continue;
			}
			CategoryPath category = new CategoryPath(CategoryPath.ROOT, path);
			String cls = SymbolUtilities.replaceInvalidChars(owner.getName(), true);
			String key = category.getPath() + "/" + cls;
			if (StlApplier.lookup(dtm, category, cls, index) != null) {
				seen.add(key);
			}
			else {
				missing.add(key);
			}
		}
		missing.removeAll(seen);
		missing.stream().limit(20).forEach(p -> println("method class without a type: " + p));
		println(missing.size() + " method classes without a type");
		return seen.size();
	}
}
