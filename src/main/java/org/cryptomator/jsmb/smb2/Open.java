package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.share.SmbOpen;

/**
 * Server-side state for one opened file/directory, wrapping the {@link SmbOpen} backend handle
 * plus SMB-specific bookkeeping. Held in {@code Session.openTable}, keyed by {@link FileId}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/96ee4d9d-9f45-48a6-9d55-cd06dfe8a22a">MS-SMB2 3.3.1.10 Per Open</a>
 */
public class Open {

	public final FileId fileId;
	public final SmbOpen backend;
	public final Session session;
	public final TreeConnect treeConnect;

	// TODO: populate more Per-Open fields as later milestones need them (oplock, lease, granted access,
	// directory enumeration cursor, etc. — see MS-SMB2 3.3.1.10).

	public Open(FileId fileId, SmbOpen backend, Session session, TreeConnect treeConnect) {
		this.fileId = fileId;
		this.backend = backend;
		this.session = session;
		this.treeConnect = treeConnect;
	}
}
