// Builds a data type archive of the MSVC C++ standard library types a PDB defines, named and filed
// where Ghidra's Microsoft demangler expects them, so the `this` of a demangled `std::` method lands
// on the real layout instead of an empty placeholder.
//
// Run it on any program whose language matches the PDB (x86 or x64 Windows), typically the msvcp DLL
// the PDB belongs to: script arguments are the PDB and the .gdt to write; without them it asks.
//
// Beside the archive it writes the classes' bases, which a data type cannot hold (an empty base takes
// no bytes, and the struct says nothing of access or virtuality), as `<archive>.classes.json`: ghicpp's
// own model of them (ghicpp.stl.StdClasses, read by ghicpp.stl.MsvcPdbClasses), so this needs the ghicpp extension installed.
// @category Data Types
// @runtime Java

import java.io.File;
import java.util.*;

import ghicpp.stl.MsvcPdbClasses;
import ghicpp.stl.StlVftables;
import ghicpp.stl.StdClasses;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractPublicMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SymbolUtilities;

public class MsvcStlArchiveScript extends GhidraScript {

	/** The namespaces whose types the archive is for; what they depend on comes along. */
	private static final Set<String> ROOTS = Set.of("std", "stdext");

	/** Typedefs the headers declare, by the instantiation they name in the demangler's spelling. */
	private static final Map<String, String> TYPEDEFS = Map.ofEntries(
		Map.entry("string", "basic_string<char,std::char_traits<char>,std::allocator<char>_>"),
		Map.entry("wstring", "basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>_>"),
		Map.entry("u16string", "basic_string<char16_t,std::char_traits<char16_t>,std::allocator<char16_t>_>"),
		Map.entry("u32string", "basic_string<char32_t,std::char_traits<char32_t>,std::allocator<char32_t>_>"),
		Map.entry("ios", "basic_ios<char,std::char_traits<char>_>"),
		Map.entry("streambuf", "basic_streambuf<char,std::char_traits<char>_>"),
		Map.entry("istream", "basic_istream<char,std::char_traits<char>_>"),
		Map.entry("ostream", "basic_ostream<char,std::char_traits<char>_>"),
		Map.entry("iostream", "basic_iostream<char,std::char_traits<char>_>"),
		Map.entry("filebuf", "basic_filebuf<char,std::char_traits<char>_>"),
		Map.entry("ifstream", "basic_ifstream<char,std::char_traits<char>_>"),
		Map.entry("ofstream", "basic_ofstream<char,std::char_traits<char>_>"),
		Map.entry("fstream", "basic_fstream<char,std::char_traits<char>_>"),
		Map.entry("stringbuf", "basic_stringbuf<char,std::char_traits<char>,std::allocator<char>_>"),
		Map.entry("istringstream", "basic_istringstream<char,std::char_traits<char>,std::allocator<char>_>"),
		Map.entry("ostringstream", "basic_ostringstream<char,std::char_traits<char>,std::allocator<char>_>"),
		Map.entry("stringstream", "basic_stringstream<char,std::char_traits<char>,std::allocator<char>_>"),
		Map.entry("wios", "basic_ios<wchar_t,std::char_traits<wchar_t>_>"),
		Map.entry("wstreambuf", "basic_streambuf<wchar_t,std::char_traits<wchar_t>_>"),
		Map.entry("wistream", "basic_istream<wchar_t,std::char_traits<wchar_t>_>"),
		Map.entry("wostream", "basic_ostream<wchar_t,std::char_traits<wchar_t>_>"),
		Map.entry("wiostream", "basic_iostream<wchar_t,std::char_traits<wchar_t>_>"));

	private final MicrosoftDemangler demangler = new MicrosoftDemangler();

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File pdbFile = args.length > 0 ? new File(args[0]) : askFile("PDB with type information", "Read");
		File out = args.length > 1 ? new File(args[1]) : askFile("Archive to write", "Write");
		if (out.exists() && !out.delete()) {
			throw new IllegalStateException("cannot replace " + out);
		}
		out.getAbsoluteFile().getParentFile().mkdirs();
		build(pdbFile, out);
	}

	private void build(File pdbFile, File out) throws Exception {
		FileDataTypeManager dtm = FileDataTypeManager.createFileArchive(out);
		try (AbstractPdb pdb = PdbParser.parse(pdbFile, new PdbReaderOptions(), monitor)) {
			pdb.deserialize();
			Map<String, DataTypePath> targets = demangledPaths(pdb);
			int methods = checkAgainstMethods(pdb, targets);
			MsvcPdbClasses.Read[] read = new MsvcPdbClasses.Read[1];
			dtm.withTransaction("MSVC STL types", () -> {
				DefaultPdbApplicator applicator = applyTypes(pdb, dtm);
				read[0] = MsvcPdbClasses.read(pdb, targets, applicator);
				CategoryPath pdbRoot = new CategoryPath(CategoryPath.ROOT, pdbFile.getName());
				int moved = refile(dtm, pdbRoot, targets);
				int pointerSize = currentProgram.getDefaultPointerSize();
				int vfptrs = fixVfptrs(dtm, pointerSize);
				// Before pruning, so the slots' function types are reached and kept.
				int vftables = StlVftables.lay(dtm, read[0].getClasses().getClasses(), pointerSize,
					(cls, slot) -> read[0].typeOf(cls, slot));
				int dropped = prune(dtm, pdbRoot);
				int typedefs = addTypedefs(dtm);
				println(String.format(
					"%s: %d std types filed by their unique names, %d unrelated types dropped, " +
						"%d typedefs, %d vfptrs sized, %d vftables; %d method classes resolve to an " +
						"archive type; %d classes with bases",
					out.getName(), moved, dropped, typedefs, vfptrs, vftables, methods,
					read[0].getClasses().getClasses().stream().filter(c -> !c.getBases().isEmpty()).count()));
			});
			read[0].getClasses().write(new File(out.getPath().replaceAll("\\.gdt$", "") + StdClasses.SUFFIX));
			dtm.save();
		}
		finally {
			dtm.close();
		}
	}

	/** The PDB's own C++ name of every defined `std` type, mapped to where the demangler files it. */
	private Map<String, DataTypePath> demangledPaths(AbstractPdb pdb) throws Exception {
		Map<String, DataTypePath> paths = new HashMap<>();
		TypeProgramInterface tpi = pdb.getTypeProgramInterface();
		for (int i = tpi.getTypeIndexMin(); i < tpi.getTypeIndexMaxExclusive(); i++) {
			monitor.checkCancelled();
			AbstractMsType type = pdb.getTypeRecord(RecordNumber.typeRecordNumber(i));
			if (!(type instanceof AbstractComplexMsType c) || c.getMsProperty().isForwardReference() ||
				c.getMangledName() == null || c.getMangledName().isEmpty()) {
				continue;
			}
			DataTypePath path = demangledPath(c.getMangledName());
			if (path != null && ROOTS.contains(path.getCategoryPath().asList().get(0))) {
				paths.putIfAbsent(spelled(c.getName()), path);
			}
		}
		return paths;
	}

	/**
	 * Gives each `vfptr` the applicator lays a pointer of [size] bytes, named `{vfptr}` as Ghidra's class
	 * tools name it: it points at a vtable shape the archive has no type for, and without an architecture
	 * a pointer to nothing defaults to 4 bytes. Returns how many it fixed.
	 */
	private int fixVfptrs(DataTypeManager dtm, int size) {
		int fixed = 0;
		List<DataType> types = new ArrayList<>();
		dtm.getAllDataTypes(types);
		for (DataType dt : types) {
			if (!(dt instanceof Structure s)) {
				continue;
			}
			for (DataTypeComponent c : s.getDefinedComponents()) {
				String name = c.getFieldName();
				if (!"vfptr".equals(name) && !"{vfptr}".equals(name) || !(c.getDataType() instanceof Pointer p)) {
					continue;
				}
				if (p.getLength() == size && "{vfptr}".equals(name)) {
					continue;
				}
				s.replaceAtOffset(c.getOffset(), new PointerDataType(p.getDataType(), size, dtm), size,
					"{vfptr}", c.getComment());
				fixed++;
			}
		}
		return fixed;
	}

	/** The applicator names a type with its spaces made underscores; key both sides that way. */
	private static String spelled(String cxxName) {
		return MsvcPdbClasses.spelled(cxxName);
	}

	/** `V?$basic_string@D…@std@@` as the demangler names it: category `/std`, the class its name. */
	private DataTypePath demangledPath(String unique) {
		try {
			DemangledDataType demangled = demangler.demangleType(
				demangler.createMangledContext(unique, demangler.createDefaultOptions(), null, null));
			if (demangled == null || demangled.getNamespace() == null) {
				return null;
			}
			return new DataTypePath(new CategoryPath(CategoryPath.ROOT, namespacePath(demangled)),
				demangled.getName());
		}
		catch (DemangledException | RuntimeException e) {
			return null;
		}
	}

	private static List<String> namespacePath(Demangled demangled) {
		LinkedList<String> path = new LinkedList<>();
		for (Demangled ns = demangled.getNamespace(); ns != null; ns = ns.getNamespace()) {
			path.addFirst(ns.getName());
		}
		return path;
	}

	/**
	 * How many distinct classes the PDB's public method symbols demangle into are among [targets]: the
	 * classes Ghidra will make `this` types of, so a low count means the spellings disagree.
	 */
	private int checkAgainstMethods(AbstractPdb pdb, Map<String, DataTypePath> targets)
			throws Exception {
		Set<DataTypePath> filed = new HashSet<>(targets.values());
		Set<DataTypePath> seen = new HashSet<>();
		Set<DataTypePath> missing = new TreeSet<>(Comparator.comparing(DataTypePath::getPath));
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null || debugInfo.getPublicSymbolInformation() == null) {
			return 0;
		}
		MsSymbolIterator iter = new SymbolGroup(pdb, 0).getSymbolIterator();
		for (long offset : debugInfo.getPublicSymbolInformation().getModifiedHashRecordSymbolOffsets()) {
			monitor.checkCancelled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext() || !(iter.peek() instanceof AbstractPublicMsSymbol pub)) {
				continue;
			}
			DataTypePath owner = methodClass(pub.getName());
			if (owner != null && ROOTS.contains(owner.getCategoryPath().asList().get(0))) {
				seen.add(owner);
				if (!filed.contains(owner)) {
					missing.add(owner);
				}
			}
		}
		seen.retainAll(filed);
		missing.stream().limit(20).forEach(p -> println("method class without a type: " + p));
		return seen.size();
	}

	/** The class a mangled member function belongs to, as the path its `this` type would take. */
	private DataTypePath methodClass(String mangled) {
		try {
			DemangledObject demangled = demangler.demangle(
				demangler.createMangledContext(mangled, demangler.createDefaultOptions(), null, null));
			if (!(demangled instanceof DemangledFunction fn) || fn.getNamespace() == null ||
				!fn.getCallingConvention().equals("__thiscall")) {
				return null;
			}
			Demangled owner = fn.getNamespace();
			if (owner.getNamespace() == null) {
				return null;
			}
			return new DataTypePath(new CategoryPath(CategoryPath.ROOT, namespacePath(owner)),
				SymbolUtilities.replaceInvalidChars(owner.getName(), true));
		}
		catch (DemangledException | RuntimeException e) {
			return null;
		}
	}

	private DefaultPdbApplicator applyTypes(AbstractPdb pdb, DataTypeManager dtm) throws Exception {
		PdbApplicatorOptions options = new PdbApplicatorOptions();
		options.setProcessingControl(PdbApplicatorControl.DATA_TYPES_ONLY);
		options.setRemapAddressUsingExistingPublicSymbols(false);
		options.setCompositeLayout(ObjectOrientedClassLayout.CLASS_HIERARCHY);
		MessageLog log = new MessageLog();
		DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb, currentProgram, dtm,
			currentProgram.getImageBase(), options, monitor, log);
		applicator.applyNoAnalysisState();
		return applicator;
	}

	/**
	 * Moves each `std` type from the PDB's own category to its demangled path, and whatever the
	 * applicator filed under a class (its `!internal` parts) along with it.
	 */
	private int refile(DataTypeManager dtm, CategoryPath pdbRoot, Map<String, DataTypePath> targets)
			throws Exception {
		Map<CategoryPath, CategoryPath> classCategories = new HashMap<>();
		List<DataType> types = new ArrayList<>();
		dtm.getAllDataTypes(types);
		int moved = 0;
		for (DataType dt : types) {
			monitor.checkCancelled();
			if (!dt.getCategoryPath().isAncestorOrSelf(pdbRoot) || dt.getCategoryPath().equals(pdbRoot)) {
				continue;
			}
			List<String> segments = relative(pdbRoot, dt.getCategoryPath());
			String cxxName = String.join("::", segments) + "::" + dt.getName();
			DataTypePath target = targets.get(spelled(cxxName));
			if (target == null) {
				if (System.getenv("STL_DEBUG") != null && dt instanceof Composite) println("MISS " + cxxName);
				continue;
			}
			classCategories.put(new CategoryPath(dt.getCategoryPath(), dt.getName()),
				new CategoryPath(target.getCategoryPath(), target.getDataTypeName()));
			dt.setNameAndCategory(target.getCategoryPath(), target.getDataTypeName());
			moved++;
		}
		for (DataType dt : types) {
			classCategories.entrySet().stream()
				.filter(e -> dt.getCategoryPath().isAncestorOrSelf(e.getKey()))
				.findFirst()
				.ifPresent(e -> moveUnder(dt, e.getKey(), e.getValue()));
		}
		return moved;
	}

	private void moveUnder(DataType dt, CategoryPath from, CategoryPath to) {
		List<String> rest = relative(from, dt.getCategoryPath());
		CategoryPath target = rest.isEmpty() ? to : new CategoryPath(to, rest);
		try {
			dt.setCategoryPath(target);
		}
		catch (Exception e) {
			printerr("cannot move " + dt.getPathName() + ": " + e.getMessage());
		}
	}

	private static List<String> relative(CategoryPath base, CategoryPath path) {
		List<String> all = path.asList();
		return all.subList(base.asList().size(), all.size());
	}

	/**
	 * Drops every type no `std` type reaches, and files the ones that stay (CRT structs such as
	 * `_Cvtvec`) under the root, as the CRT archives would.
	 */
	private int prune(DataTypeManager dtm, CategoryPath pdbRoot) throws Exception {
		List<DataType> types = new ArrayList<>();
		dtm.getAllDataTypes(types);
		Set<DataType> keep = new HashSet<>();
		Deque<DataType> work = new ArrayDeque<>();
		for (DataType dt : types) {
			if (!(dt instanceof FunctionDefinition) && !dt.getCategoryPath().isAncestorOrSelf(pdbRoot) &&
				!dt.getCategoryPath().isRoot() && ROOTS.contains(dt.getCategoryPath().asList().get(0))) {
				work.add(dt);
			}
		}
		while (!work.isEmpty()) {
			DataType dt = work.pop();
			if (keep.add(dt)) {
				work.addAll(dependencies(dt));
			}
		}
		List<DataType> drop = types.stream().filter(dt -> !keep.contains(dt)).toList();
		dtm.remove(drop, monitor);
		for (DataType dt : keep) {
			if (dt.getCategoryPath().isAncestorOrSelf(pdbRoot) && !dt.isDeleted()) {
				moveUnder(dt, pdbRoot, CategoryPath.ROOT);
			}
		}
		removeEmptyCategories(dtm.getRootCategory());
		return drop.size();
	}

	private void removeEmptyCategories(Category category) {
		for (Category sub : category.getCategories()) {
			removeEmptyCategories(sub);
			if (sub.getDataTypes().length == 0 && sub.getCategories().length == 0) {
				category.removeEmptyCategory(sub.getName(), monitor);
			}
		}
	}

	private static List<DataType> dependencies(DataType dt) {
		List<DataType> deps = new ArrayList<>();
		if (dt instanceof Composite c) {
			for (DataTypeComponent component : c.getDefinedComponents()) {
				deps.add(component.getDataType());
			}
		}
		else if (dt instanceof Pointer p && p.getDataType() != null) {
			deps.add(p.getDataType());
		}
		else if (dt instanceof Array a) {
			deps.add(a.getDataType());
		}
		else if (dt instanceof TypeDef t) {
			deps.add(t.getDataType());
		}
		else if (dt instanceof FunctionDefinition f) {
			deps.add(f.getReturnType());
			for (ParameterDefinition param : f.getArguments()) {
				deps.add(param.getDataType());
			}
		}
		return deps;
	}

	private int addTypedefs(DataTypeManager dtm) {
		CategoryPath std = new CategoryPath(CategoryPath.ROOT, "std");
		int added = 0;
		for (Map.Entry<String, String> e : TYPEDEFS.entrySet()) {
			DataType target = dtm.getDataType(std, e.getValue());
			if (target != null) {
				dtm.addDataType(new TypedefDataType(std, e.getKey(), target, dtm),
					DataTypeConflictHandler.REPLACE_HANDLER);
				added++;
			}
		}
		return added;
	}
}
