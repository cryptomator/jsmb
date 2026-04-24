package org.cryptomator.jsmb.share;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.stream.Stream;

/**
 * A handle to a single opened file or directory, returned by {@link SmbShare#open}. Each handle
 * carries a server-assigned {@link FileId} and lives until {@link #close()} is invoked.
 * <p>
 * File-only methods ({@link #read}, {@link #write}, {@link #flush}, {@link #setEndOfFile}) may
 * throw {@link UnsupportedOperationException} when invoked on a directory handle; directory-only
 * methods ({@link #listChildren}) likewise on a file handle. The SMB2 command handler is expected
 * to gate by the {@link FileStandardInfo#directory()} flag it received from {@link #queryStandard()}.
 * <p>
 * TODO: split this into a sealed hierarchy {@code SmbHandle permits FileHandle, DirectoryHandle}
 * so the compiler enforces "only call {@code read}/{@code write} on a file" and
 * "only call {@code listChildren} on a directory". Deferred until a concrete caller — most likely
 * {@code QUERY_DIRECTORY} in milestone M6 — makes the type-check valuable enough to justify the
 * extra interface surface and the type-check at every SMB command site.
 */
public interface SmbOpen extends AutoCloseable {

	FileId fileId();

	FileBasicInfo queryBasic() throws IOException;

	FileStandardInfo queryStandard() throws IOException;

	/**
	 * Update timestamps and attribute bits. A non-null field overwrites; a null {@code Instant}
	 * leaves the existing timestamp unchanged, and {@code fileAttributes == 0} leaves attributes alone.
	 */
	void setBasic(FileBasicInfo info) throws IOException;

	/**
	 * Rename (and/or move) this open's target to {@code newPath} relative to the share root.
	 */
	void rename(String newPath, boolean replaceIfExists) throws IOException;

	/**
	 * Mark this open for deletion; the backing file/directory is unlinked when {@link #close()} runs.
	 */
	void markForDeletion();

	/**
	 * Read up to {@code dst.remaining()} bytes starting at {@code offset}, advancing {@code dst}'s
	 * position by the number of bytes actually read. Returns -1 at end-of-file.
	 */
	int read(ByteBuffer dst, long offset) throws IOException;

	/**
	 * Write {@code src.remaining()} bytes starting at {@code offset}, advancing {@code src}'s position.
	 */
	int write(ByteBuffer src, long offset) throws IOException;

	void flush() throws IOException;

	/**
	 * Truncate or extend the file to exactly {@code length} bytes.
	 */
	void setEndOfFile(long length) throws IOException;

	/**
	 * Stream the children of a directory handle. The pattern uses SMB wildcards ({@code *}, {@code ?});
	 * {@code null} or {@code "*"} means "all children". The returned stream must be closed by the caller.
	 * <p>
	 * Implementations MUST prepend the synthetic self- and parent-entries that real SMB servers emit,
	 * filtered by the same {@code pattern}:
	 * <ul>
	 *   <li>{@code "."} — always, representing this directory.</li>
	 *   <li>{@code ".."} — only when this handle is <em>not</em> the share root; represents the parent.</li>
	 * </ul>
	 * Reusing this directory's own metadata for both is acceptable; clients don't rely on accurate
	 * timestamps / sizes on the pseudo-entries. Omitting them makes empty directories round-trip as
	 * {@code STATUS_NO_SUCH_FILE}, which many clients surface to the end user as a hard "not found"
	 * error instead of rendering an empty listing.
	 */
	Stream<DirEntry> listChildren(String pattern) throws IOException;

	@Override
	void close() throws IOException;
}
