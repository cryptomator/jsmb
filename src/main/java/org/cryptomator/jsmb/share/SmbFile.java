package org.cryptomator.jsmb.share;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * A {@link SmbOpen} backed by a regular file. Exposes the byte-range methods that SMB2 {@code READ} /
 * {@code WRITE} / {@code FLUSH} / {@code SET_INFO(FILE_END_OF_FILE)} dispatch to.
 */
public non-sealed interface SmbFile extends SmbOpen {

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
}
