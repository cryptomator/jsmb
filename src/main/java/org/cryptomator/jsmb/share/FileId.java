package org.cryptomator.jsmb.share;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.UUID;

/**
 * A 16-byte SMB2 {@code FileId}: a pair of 64-bit handles that together identify an open object.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f1d9b40d-e335-45fc-9d0b-199a31ede4c3">MS-SMB2 2.2.14.1 SMB2_FILEID</a>
 */
public record FileId(long persistentHandle, long volatileHandle) {

	public static final int SIZE = 16;

	/**
	 * The sentinel {@code FileId} (all 0xFF bytes) used for IOCTL/FSCTL requests that don't reference an open.
	 */
	public static final FileId NONE = new FileId(-1L, -1L);

	/**
	 * Generates a random, non-zero {@link FileId} suitable for a newly opened object.
	 */
	public static FileId random() {
		var uuid = UUID.randomUUID();
		return new FileId(uuid.getMostSignificantBits(), uuid.getLeastSignificantBits());
	}

	public static FileId fromSegment(MemorySegment segment) {
		if (segment.byteSize() < SIZE) {
			throw new IllegalArgumentException("FileId segment must be at least " + SIZE + " bytes");
		}
		return new FileId(segment.get(Layouts.LE_INT64, 0), segment.get(Layouts.LE_INT64, 8));
	}

	public void writeTo(MemorySegment segment) {
		if (segment.byteSize() < SIZE) {
			throw new IllegalArgumentException("FileId segment must be at least " + SIZE + " bytes");
		}
		segment.set(Layouts.LE_INT64, 0, persistentHandle);
		segment.set(Layouts.LE_INT64, 8, volatileHandle);
	}
}
