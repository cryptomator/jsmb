package org.cryptomator.jsmb.share;

import java.io.IOException;

/**
 * A handle to a single opened filesystem entry, returned by {@link SmbShare#open}. Each handle carries a
 * server-assigned {@link FileId} and lives until {@link #close()} is invoked.
 *
 * <p>This is a sealed root: every handle is either a {@link SmbFile} or a {@link SmbDirectory}. Handlers pattern-match
 * on the concrete subtype so the compiler enforces "only call {@code read}/{@code write} on a file" and "only call
 * {@code listChildren} on a directory" — the subtype captures what the on-disk entry actually is, not what the client
 * thinks it is.
 */
public sealed interface SmbOpen extends AutoCloseable permits SmbFile, SmbDirectory {

	FileId fileId();

	/**
	 * Whether the backend file/directory existed on disk at the moment {@link SmbShare#open} was invoked.
	 * The {@code CREATE} handler needs this to distinguish {@code FILE_OPENED} vs {@code FILE_CREATED} for
	 * {@code FILE_OPEN_IF}, and {@code FILE_OVERWRITTEN} vs {@code FILE_CREATED} for {@code FILE_OVERWRITE_IF}
	 * (MS-SMB2 2.2.14 {@code CreateAction}).
	 */
	boolean existedBeforeOpen();

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

	@Override
	void close() throws IOException;
}
