package ghidra.program.database.sourcemap;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Ghidra's source-file identity, which arrives in 11.3. Java, matching the original, so Kotlin sees
 * the same synthetic {@code .path} / {@code .filename} and the same {@code getFilename()}.
 *
 * <p>Every source we build carries {@code SourceFileIdType.NONE} — stabs records no file hash — so
 * the path alone is the identity, and equality, hashing and ordering reduce to it exactly as they do
 * in the real class.
 */
public final class SourceFile implements Comparable<SourceFile> {
	private final String path;
	private final String filename;

	public SourceFile(String pathToValidate) {
		if (pathToValidate == null || pathToValidate.isBlank()) {
			throw new IllegalArgumentException("pathToValidate cannot be null or blank");
		}
		try {
			path = new URI("file", null, pathToValidate, null).normalize().getPath();
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("path not valid: " + e.getMessage());
		}
		if (path.endsWith("/")) {
			throw new IllegalArgumentException("SourceFile URI must represent a file (not a directory)");
		}
		if (path.startsWith("/../")) {
			throw new IllegalArgumentException("path must be absolute after normalization");
		}
		filename = path.substring(path.lastIndexOf("/") + 1);
	}

	public String getPath() {
		return path;
	}

	public String getFilename() {
		return filename;
	}

	@Override
	public int compareTo(SourceFile other) {
		return path.compareTo(other.path);
	}

	@Override
	public boolean equals(Object o) {
		return this == o || (o instanceof SourceFile other && path.equals(other.path));
	}

	@Override
	public int hashCode() {
		return path.hashCode();
	}

	@Override
	public String toString() {
		return path;
	}
}
