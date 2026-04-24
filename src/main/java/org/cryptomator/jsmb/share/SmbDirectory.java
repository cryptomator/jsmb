package org.cryptomator.jsmb.share;

import java.io.IOException;
import java.util.stream.Stream;

/**
 * A {@link SmbOpen} backed by a directory. Exposes the child-enumeration method that SMB2 {@code QUERY_DIRECTORY}
 * dispatches to.
 */
public non-sealed interface SmbDirectory extends SmbOpen {

	/**
	 * Stream the children of this directory handle. The pattern uses SMB wildcards ({@code *}, {@code ?});
	 * {@code null} or {@code "*"} means "all children". The returned stream must be closed by the caller.
	 *
	 * <p>Implementations MUST prepend the synthetic self- and parent-entries that real SMB servers emit,
	 * filtered by the same {@code pattern}:
	 * <ul>
	 *   <li>{@code "."} — always, representing this directory.</li>
	 *   <li>{@code ".."} — only when this handle is <em>not</em> the share root; represents the parent.</li>
	 * </ul>
	 * Reusing this directory's own metadata for both is acceptable; clients don't rely on accurate timestamps /
	 * sizes on the pseudo-entries. Omitting them makes empty directories round-trip as {@code STATUS_NO_SUCH_FILE},
	 * which many clients surface to the end user as a hard "not found" error instead of rendering an empty listing.
	 */
	Stream<DirEntry> listChildren(String pattern) throws IOException;
}
