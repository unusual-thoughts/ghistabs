// Fails when an archive built from the probe and one built from Microsoft's own runtime PDB disagree
// on the size or the field offsets of any std type both define. Arguments: archive, reference.
// @category Data Types
// @runtime Java

import java.io.File;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CompareStlArchives extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		FileDataTypeManager archive = FileDataTypeManager.openFileArchive(new File(args[0]), false);
		FileDataTypeManager reference = FileDataTypeManager.openFileArchive(new File(args[1]), false);
		try {
			List<String> mismatches = new ArrayList<>();
			int compared = 0;
			Iterator<Composite> it = archive.getAllComposites();
			while (it.hasNext()) {
				Composite ours = it.next();
				if (!ours.getCategoryPath().getPath().startsWith("/std")) {
					continue;
				}
				DataType theirs = reference.getDataType(ours.getDataTypePath());
				if (!(theirs instanceof Composite ref) || ref.isNotYetDefined() || ours.isNotYetDefined()) {
					continue;
				}
				compared++;
				String diff = difference(ours, ref);
				if (diff != null) {
					mismatches.add(ours.getPathName() + ": " + diff);
				}
			}
			println(String.format("%s vs %s: %d std types compared, %d differ", args[0], args[1],
				compared, mismatches.size()));
			mismatches.forEach(this::println);
			if (compared == 0 || !mismatches.isEmpty()) {
				throw new IllegalStateException(compared == 0 ? "no std type in common" : "layouts differ");
			}
		}
		finally {
			archive.close();
			reference.close();
		}
	}

	private static String difference(Composite ours, Composite ref) {
		if (ours.getLength() != ref.getLength()) {
			return "size " + ours.getLength() + " vs " + ref.getLength();
		}
		List<Integer> ourOffsets = offsets(ours);
		List<Integer> refOffsets = offsets(ref);
		return ourOffsets.equals(refOffsets) ? null : "fields at " + ourOffsets + " vs " + refOffsets;
	}

	/** Where its fields start, empty bases left out: PDBs of different ages record those or not. */
	private static List<Integer> offsets(Composite c) {
		return Arrays.stream(c.getDefinedComponents())
			.filter(m -> !isEmpty(m.getDataType()))
			.map(DataTypeComponent::getOffset)
			.toList();
	}

	private static boolean isEmpty(DataType dt) {
		return dt instanceof Composite c &&
			Arrays.stream(c.getDefinedComponents()).allMatch(m -> isEmpty(m.getDataType()));
	}
}
