package org.cryptomator.jsmb.share;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.UUID;

/**
 * A 16-byte SMB2 {@code FileId}: a pair of 64-bit handles that together identify an open object.
 *
 * @param persistentHandle identifies the open across reconnects (durable / persistent handles)
 * @param volatileHandle   identifies the open within the current TCP connection
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f1d9b40d-e335-45fc-9d0b-199a31ede4c3">MS-SMB2 2.2.14.1 SMB2_FILEID</a>
 */
public record FileId(long persistentHandle, long volatileHandle) {

	/** Wire size of a {@code FileId} in bytes. */
	public static final int SIZE = 16;

	/**
	 * The sentinel {@code FileId} (all 0xFF bytes) used for IOCTL/FSCTL requests that don't reference an open.
	 */
	public static final FileId NONE = new FileId(-1L, -1L);

	/**
	 * Generates a random, non-zero {@link FileId} suitable for a newly opened object.
	 *
	 * @return a freshly generated {@code FileId} backed by a random {@link UUID}
	 */
	public static FileId random() {
		var uuid = UUID.randomUUID();
		return new FileId(uuid.getMostSignificantBits(), uuid.getLeastSignificantBits());
	}

	/**
	 * Reads the 16-byte wire representation from the start of {@code segment}.
	 *
	 * @param segment memory holding at least {@value #SIZE} bytes in SMB2 wire layout
	 * @return the parsed {@code FileId}
	 * @throws IllegalArgumentException if {@code segment} is shorter than {@value #SIZE} bytes
	 */
	public static FileId fromSegment(MemorySegment segment) {
		if (segment.byteSize() < SIZE) {
			throw new IllegalArgumentException("FileId segment must be at least " + SIZE + " bytes");
		}
		return new FileId(segment.get(Layouts.LE_INT64, 0), segment.get(Layouts.LE_INT64, 8));
	}

	/**
	 * Writes this {@code FileId} in the 16-byte SMB2 wire layout to the start of {@code segment}.
	 *
	 * @param segment target memory with at least {@value #SIZE} writable bytes
	 * @throws IllegalArgumentException if {@code segment} is shorter than {@value #SIZE} bytes
	 */
	public void writeTo(MemorySegment segment) {
		if (segment.byteSize() < SIZE) {
			throw new IllegalArgumentException("FileId segment must be at least " + SIZE + " bytes");
		}
		segment.set(Layouts.LE_INT64, 0, persistentHandle);
		segment.set(Layouts.LE_INT64, 8, volatileHandle);
	}
}
