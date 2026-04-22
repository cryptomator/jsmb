package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.ThreadLocalRandom;

/**
 * A 16-byte SMB2 {@code FileId}: a pair of 64-bit handles that together identify an open object.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3088d198-ad72-4e1e-92cd-ee65a0a6c14b">MS-SMB2 2.2.14.1 SMB2_FILEID</a>
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
		var rnd = ThreadLocalRandom.current();
		long p, v;
		do {
			p = rnd.nextLong();
			v = rnd.nextLong();
		} while (p == 0L || v == 0L || (p == -1L && v == -1L));
		return new FileId(p, v);
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
