package org.cryptomator.jsmb.util;

import java.lang.foreign.MemorySegment;

public class MemorySegments {

	private MemorySegments() {
		// no-op
	}

	/**
	 * Creates an on-heap copy of the given MemorySegment.
	 * @param original Original MemorySegment
	 * @return Copy of the original MemorySegment
	 * @throws IllegalArgumentException If the resulting MemorySegment is too large to create (backed by a byte[])
	 */
	public static MemorySegment copy(MemorySegment original) throws IllegalArgumentException {
		if (original.byteSize() > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("MemorySegment too large to copy");
		}
		var result = MemorySegment.ofArray(new byte[(int) original.byteSize()]);
		return result.copyFrom(original);
	}

	/**
	 * Creates a new on-heap memory segment, containing the contents of the two given segments.
	 * @param left Left MemorySegment
	 * @param right Right MemorySegment
	 * @return Concatenated MemorySegment
	 * @throws IllegalArgumentException If the resulting MemorySegment is too large to create (backed by a byte[])
	 */
	public static MemorySegment concat(MemorySegment left, MemorySegment right) {
		if (left.byteSize() + right.byteSize() > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("MemorySegment too large to concat");
		}
		var result = MemorySegment.ofArray(new byte[(int) (left.byteSize() + right.byteSize())]);
		result.copyFrom(left);
		result.asSlice(left.byteSize()).copyFrom(right);
		return result;
	}

}
