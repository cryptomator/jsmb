package org.cryptomator.jsmb.smb2.crypto;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 TRANSFORM_HEADER wrapping an encrypted SMB2 message.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa">2.2.41 SMB2 TRANSFORM_HEADER</a>
 */
public record TransformHeader(MemorySegment segment) {

	public static final int STRUCTURE_SIZE = 52;
	public static final int PROTOCOL_ID = 0x424D53FD; // 0xFD S M B
	public static final char FLAG_ENCRYPTED = 0x0001;

	public TransformHeader {
		if (segment.byteSize() < STRUCTURE_SIZE) {
			throw new IllegalArgumentException("TRANSFORM_HEADER segment too small: " + segment.byteSize());
		}
	}

	public int protocolId() {
		return segment.get(Layouts.LE_INT32, 0);
	}

	public byte[] signature() {
		return segment.asSlice(4, 16).toArray(Layouts.BYTE);
	}

	public byte[] nonce() {
		return segment.asSlice(20, 16).toArray(Layouts.BYTE);
	}

	public int originalMessageSize() {
		return segment.get(Layouts.LE_INT32, 36);
	}

	public char flags() {
		return segment.get(Layouts.LE_UINT16, 42);
	}

	public long sessionId() {
		return segment.get(Layouts.LE_INT64, 44);
	}

	public static TransformHeaderBuilder builder() {
		return new TransformHeaderBuilder();
	}
}
