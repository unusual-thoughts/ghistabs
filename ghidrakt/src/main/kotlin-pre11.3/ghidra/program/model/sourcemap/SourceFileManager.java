package ghidra.program.model.sourcemap;

import java.util.List;

import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;

/**
 * The manager 11.3 introduced. Java, like the original, so Kotlin synthesises {@code .allSourceFiles}
 * and {@code .mappedSourceFiles} from these getters exactly as it does for the real interface.
 *
 * <p>{@code getSourceMapEntryIterator} returns a {@link List} rather than Ghidra's
 * {@code SourceMapEntryIterator}: that type is both an {@code Iterator} and an {@code Iterable}, and
 * the only thing asked of it is {@code firstOrNull()}, which a list answers the same way.
 */
public interface SourceFileManager {

	public boolean addSourceFile(SourceFile sourceFile);

	public SourceMapEntry addSourceMapEntry(SourceFile sourceFile, int lineNumber, Address baseAddr,
			long length);

	public void transferSourceMapEntries(SourceFile source, SourceFile target);

	public List<SourceFile> getAllSourceFiles();

	public List<SourceFile> getMappedSourceFiles();

	public List<SourceMapEntry> getSourceMapEntries(SourceFile sourceFile);

	public List<SourceMapEntry> getSourceMapEntries(Address address);

	public List<SourceMapEntry> getSourceMapEntryIterator(Address address, boolean forward);
}
