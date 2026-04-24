package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.share.FileId;

/**
 * Mixin for messages whose wire format has a {@link FileId} field referencing a previously opened handle.
 *
 * <p>Compound chains with the {@code SMB2_FLAGS_RELATED_OPERATIONS} flag may substitute the sentinel
 * {@link FileId#NONE} to mean "use the FileId produced by the previous operation in the chain" — typically the CREATE
 * that precedes it. {@link #substituteFileIdIfSentinel} performs that substitution in-place.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cb250ec7-d2d7-4a9a-9635-3e7770bfdae9>MS-SMB2 3.3.5.2.7 Handling Compounded Requests</a>
 */
public interface FileIdCarrying {

	FileId fileId();

	void fileId(FileId fileId);

	default void substituteFileIdIfSentinel(FileId chainedFileId) {
		if (fileId().equals(FileId.NONE)) {
			fileId(chainedFileId);
		}
	}
}
