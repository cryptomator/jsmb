package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.share.FileId;

/**
 * Mixin for messages whose wire format has a {@link FileId} field referencing a previously opened handle.
 *
 * <p>An operation flagged with {@code SMB2_FLAGS_RELATED_OPERATIONS} works on the FileId of the operation preceding it in a
 * compounded request — typically a CREATE — whatever its own field says, which usually is {@link FileId#NONE}.
 * {@link CompoundChain} keeps track of that FileId, and the setter puts it in place before the operation gets dispatched.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46dd4182-62d3-4e30-9fe5-e2ec124edca1">MS-SMB2 3.3.5.2.7.2 Handling Compounded Related Requests</a>
 */
public interface FileIdCarrying {

	FileId fileId();

	void fileId(FileId fileId);
}
