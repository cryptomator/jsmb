package org.cryptomator.jsmb.util;

/**
 * Deterministic 64-bit hash used as a synthetic pseudo-inode for MS-FSCC fields backends don't track natively — e.g.
 * {@code FileInternalInformation.IndexNumber} and {@code FileIdBothDirectoryInformation.FileReferenceNumber}.
 *
 * <p>Not collision-free; meant for test-grade backends where a real filesystem inode isn't available. Callers hash the
 * full share-relative path of a file, so that a directory listing and a query on an open of the file report the same ID.
 */
public final class InodeHash {

	private InodeHash() {}

	public static long of(String identity) {
		long h = 1125899906842597L; // large prime seed
		for (int i = 0; i < identity.length(); i++) {
			h = 31 * h + identity.charAt(i);
		}
		return h;
	}
}
