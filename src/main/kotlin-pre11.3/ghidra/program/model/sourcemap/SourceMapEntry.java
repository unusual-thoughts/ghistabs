package ghidra.program.model.sourcemap;

import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * Ghidra's source map arrives in 11.3. Declared in Java, like the original, so Kotlin synthesises the
 * same {@code .lineNumber} / {@code .baseAddress} properties from these getters — a Kotlin interface
 * would not, and every call site would have to change shape.
 */
public interface SourceMapEntry extends Comparable<SourceMapEntry> {
	public int getLineNumber();

	public SourceFile getSourceFile();

	public Address getBaseAddress();

	public long getLength();

	public AddressRange getRange();
}
