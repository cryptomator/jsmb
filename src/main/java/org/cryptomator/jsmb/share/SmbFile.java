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
	 *
	 * @param dst    destination buffer; its position is advanced by the return value
	 * @param offset absolute byte offset within the file to read from
	 * @return number of bytes read, or {@code -1} at end-of-file
	 * @throws IOException if the backend cannot satisfy the read
	 */
	int read(ByteBuffer dst, long offset) throws IOException;

	/**
	 * Write {@code src.remaining()} bytes starting at {@code offset}, advancing {@code src}'s position.
	 *
	 * @param src    source buffer; its position is advanced by the return value
	 * @param offset absolute byte offset within the file to write at
	 * @return number of bytes written
	 * @throws IOException if the backend cannot satisfy the write
	 */
	int write(ByteBuffer src, long offset) throws IOException;

	/**
	 * Flush any buffered writes to durable storage.
	 *
	 * @throws IOException if the backend cannot flush
	 */
	void flush() throws IOException;

	/**
	 * Truncate or extend the file to exactly {@code length} bytes.
	 *
	 * @param length new file size in bytes
	 * @throws IOException if the backend cannot resize the file
	 */
	void setEndOfFile(long length) throws IOException;
}
