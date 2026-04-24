package org.cryptomator.jsmb.share;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;

/**
 * A filesystem-like backend that an embedder registers with {@code TcpServer.registerShare(name, share)}
 * to back an SMB share. One {@code SmbShare} instance serves many concurrent opens.
 * <p>
 * Paths passed to this SPI are <strong>forward-slash delimited and relative to the share root</strong>
 * (the leading slash is optional; both {@code "foo/bar"} and {@code "/foo/bar"} mean the same entry).
 * The root itself is the empty string {@code ""} or {@code "/"}. Separator translation from SMB's
 * backslash form is the caller's concern.
 *
 * <p>Exceptions thrown by {@link #open} are mapped to NT status codes by the SMB2 command handler:
 * <ul>
 *   <li>{@link NoSuchFileException} → {@code STATUS_OBJECT_NAME_NOT_FOUND}</li>
 *   <li>{@link FileAlreadyExistsException} → {@code STATUS_OBJECT_NAME_COLLISION}</li>
 *   <li>{@link AccessDeniedException} → {@code STATUS_ACCESS_DENIED}</li>
 *   <li>any other {@link IOException} → {@code STATUS_UNEXPECTED_IO_ERROR}</li>
 * </ul>
 */
public interface SmbShare {

	/**
	 * Open (or create) a file or directory under the share root. The returned handle is owned by the
	 * caller until {@link SmbOpen#close()} is invoked.
	 *
	 * @param path   forward-slash delimited path relative to the share root, or {@code ""} / {@code "/"} for the root itself
	 * @param params NT access / share / disposition / options passed through from {@code CREATE}
	 * @return an open handle; never {@code null}
	 * @throws IOException if the backend refuses the open; see the class-level mapping to NT status codes
	 */
	SmbOpen open(String path, OpenParams params) throws IOException;

	/**
	 * Returns volume-level attributes used by {@code QUERY_INFO} / {@code FileFsAttributeInformation}.
	 *
	 * @return the volume's attribute flags, max component length, and filesystem-type name
	 */
	FsAttributes fsAttributes();

	/**
	 * Returns volume size information used by {@code QUERY_INFO} / {@code FileFsSizeInformation}.
	 *
	 * @return the volume's total / free unit counts and sector geometry
	 * @throws IOException if the backend cannot retrieve current volume sizing
	 */
	FsSize fsSize() throws IOException;
}
