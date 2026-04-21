package org.cryptomator.jsmb.smb2.crypto;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record TransformHeaderBuilder(MemorySegment segment) {

	public TransformHeaderBuilder {
		segment.set(Layouts.LE_INT32, 0, TransformHeader.PROTOCOL_ID);
	}

	public TransformHeaderBuilder() {
		this(MemorySegment.ofArray(new byte[TransformHeader.STRUCTURE_SIZE]));
	}

	public TransformHeaderBuilder signature(byte[] signature) {
		if (signature.length != 16) {
			throw new IllegalArgumentException("Signature must be 16 bytes");
		}
		segment.asSlice(4, 16).copyFrom(MemorySegment.ofArray(signature));
		return this;
	}

	public TransformHeaderBuilder nonce(byte[] nonce) {
		if (nonce.length != 16) {
			throw new IllegalArgumentException("Nonce field must be 16 bytes (zero-pad if cipher uses fewer)");
		}
		segment.asSlice(20, 16).copyFrom(MemorySegment.ofArray(nonce));
		return this;
	}

	public TransformHeaderBuilder originalMessageSize(int size) {
		segment.set(Layouts.LE_INT32, 36, size);
		return this;
	}

	public TransformHeaderBuilder flags(char flags) {
		segment.set(Layouts.LE_UINT16, 42, flags);
		return this;
	}

	public TransformHeaderBuilder sessionId(long sessionId) {
		segment.set(Layouts.LE_INT64, 44, sessionId);
		return this;
	}

	public TransformHeader build() {
		return new TransformHeader(segment.asReadOnly());
	}
}
