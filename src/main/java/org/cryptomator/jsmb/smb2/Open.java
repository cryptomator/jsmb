package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.share.DirEntry;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.SmbOpen;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

/**
 * Server-side state for one opened file/directory, wrapping the {@link SmbOpen} backend handle
 * plus SMB-specific bookkeeping. Held in {@code Session.openTable}, keyed by {@link FileId}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/96ee4d9d-9f45-48a6-9d55-cd06dfe8a22a">MS-SMB2 3.3.1.10 Per Open</a>
 */
public class Open {

	private static final Logger LOG = LoggerFactory.getLogger(Open.class);

	public final FileId fileId;
	public final SmbOpen backend;
	public final Session session;
	public final TreeConnect treeConnect;

	/**
	 * Normalised path relative to the share root, as passed to {@code SmbShare.open(...)}.
	 * Forward-slash delimited (translation from backslashes happens in the CREATE handler).
	 * Empty string for the share root. Changes when the open gets renamed.
	 */
	public String path;

	/** The {@code CreateOptions} the client opened the file with (MS-SMB2 2.2.13). */
	public final int createOptions;

	/**
	 * The rights the client holds on the open, which requests on it are checked against. Made up of {@link AccessMask} bits other than the generic ones.
	 * <p>
	 * MS-SMB2 3.3.5.9 has {@code Open.GrantedAccess} be all rights for a share without {@code ConnectSecurity} and leaves it to the object store
	 * to hold the client to what it asked for (MS-FSA 2.1.5.1). There is no such object store beneath this server, so this is the latter's notion of granted access.
	 */
	public final int grantedAccess;

	/**
	 * Cached snapshot of the directory listing for the current {@code QUERY_DIRECTORY} enumeration.
	 * {@code null} until the first {@code QUERY_DIRECTORY} on this Open; repopulated on
	 * {@code SL_RESTART_SCAN} / {@code SL_REOPEN}.
	 */
	public @Nullable List<DirEntry> directoryEntries;

	/** Cursor into {@link #directoryEntries} — next index to return. */
	public int nextDirectoryIndex;

	// TODO: populate more Per-Open fields as later milestones need them (oplock, lease, etc.)

	/**
	 * @param fileId        the identifier the client refers to the open by
	 * @param backend       the handle of the share backend
	 * @param session       the session the open belongs to
	 * @param treeConnect   the tree connect the open was created on
	 * @param path          forward-slash delimited path relative to the share root
	 * @param createOptions the {@code CreateOptions} of the CREATE request
	 * @param grantedAccess the rights the client holds on the open, see {@link AccessMask#grantedFor(int)}
	 */
	public Open(FileId fileId, SmbOpen backend, Session session, TreeConnect treeConnect, String path, int createOptions, int grantedAccess) {
		this.fileId = fileId;
		this.backend = backend;
		this.session = session;
		this.treeConnect = treeConnect;
		this.path = path;
		this.createOptions = createOptions;
		this.grantedAccess = grantedAccess;
	}

	/**
	 * Tells whether the client holds certain rights on the open.
	 *
	 * @param access one or more {@link AccessMask} bits
	 * @return {@code true} if all of them are granted
	 */
	public boolean isGranted(int access) {
		return (grantedAccess & access) == access;
	}

	/**
	 * Releases the backend handle, as part of closing an open (MS-SMB2 3.3.4.17). An open created with {@code FILE_DELETE_ON_CLOSE} has its target deleted,
	 * unless that is a directory with entries (MS-FSA 2.1.5.5). A failure is logged and otherwise ignored, as the open is given up either way.
	 * Removing the open from {@code Session.openTable} is up to the caller.
	 */
	public void close() {
		if ((createOptions & OpenParams.OPTION_DELETE_ON_CLOSE) != 0) {
			try {
				backend.setDeletePending(true);
			} catch (IOException e) {
				LOG.debug("'{}' is not deleted on close", path, e);
			}
		}
		try {
			backend.close();
		} catch (IOException e) {
			LOG.warn("Closing '{}' failed", path, e);
		}
	}
}
