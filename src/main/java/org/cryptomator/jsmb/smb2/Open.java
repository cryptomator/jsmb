package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.share.DirEntry;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.share.SmbOpen;
import org.jetbrains.annotations.Nullable;

import java.util.List;

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

	/**
	 * Normalised path relative to the share root, as passed to {@code SmbShare.open(...)}.
	 * Forward-slash delimited (translation from backslashes happens in the CREATE handler).
	 * Empty string for the share root.
	 */
	public final String path;

	/**
	 * Cached snapshot of the directory listing for the current {@code QUERY_DIRECTORY} enumeration.
	 * {@code null} until the first {@code QUERY_DIRECTORY} on this Open; repopulated on
	 * {@code SL_RESTART_SCAN} / {@code SL_REOPEN}.
	 */
	public @Nullable List<DirEntry> directoryEntries;

	/** Cursor into {@link #directoryEntries} — next index to return. */
	public int nextDirectoryIndex;

	// TODO: populate more Per-Open fields as later milestones need them (oplock, lease, granted access, etc.)

	public Open(FileId fileId, SmbOpen backend, Session session, TreeConnect treeConnect, String path) {
		this.fileId = fileId;
		this.backend = backend;
		this.session = session;
		this.treeConnect = treeConnect;
		this.path = path;
	}
}
