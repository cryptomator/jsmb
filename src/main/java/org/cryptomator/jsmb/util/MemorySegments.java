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
		long size = Math.addExact(left.byteSize() + right.byteSize());
		if (size > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("MemorySegment too large to concat");
		}
		var result = MemorySegment.ofArray(new byte[(int) size]);
		MemorySegment.copy(left, 0, result, 0, left.byteSize());
		MemorySegment.copy(right, 0, result, left.byteSize(), right.byteSize());
		return result;
	}

	/**
	 * Creates a new on-heap copy of the given segment, adding a padding in order to align the resulting segment to the given alignment.
	 * @param segment original segment
	 * @param alignment number of bytes to align to
	 * @return If the original segment is already aligned, the original segment is returned. Otherwise, a new segment is created, containing the original segment and padding bytes.
	 */
	public static MemorySegment pad(MemorySegment segment, int alignment) {
		if (segment.byteSize() % alignment == 0) {
			return segment;
		}
		var padding = alignment - (segment.byteSize() % alignment);
		var result = MemorySegment.ofArray(new byte[(int) (segment.byteSize() + padding)]);
		MemorySegment.copy(segment, 0, result, 0, segment.byteSize());
		return result;
	}
}
