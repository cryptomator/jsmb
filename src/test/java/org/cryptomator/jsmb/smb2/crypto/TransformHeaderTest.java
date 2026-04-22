package org.cryptomator.jsmb.smb2.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;

class TransformHeaderTest {

	@Test
	@DisplayName("Setters and getters round-trip every TRANSFORM_HEADER field")
	public void testRoundTrip() {
		byte[] signature = new byte[16];
		byte[] nonce = new byte[16];
		Arrays.fill(signature, (byte) 0x55);
		Arrays.fill(nonce, (byte) 0x77);
		int originalMessageSize = 0x1234_5678;
		char flags = TransformHeader.FLAG_ENCRYPTED;
		long sessionId = 0xCAFE_BABE_DEAD_BEEFL;

		var header = TransformHeader.builder()
				.signature(signature)
				.nonce(nonce)
				.originalMessageSize(originalMessageSize)
				.flags(flags)
				.sessionId(sessionId)
				.build();

		Assertions.assertEquals(TransformHeader.PROTOCOL_ID, header.protocolId());
		Assertions.assertArrayEquals(signature, header.signature());
		Assertions.assertArrayEquals(nonce, header.nonce());
		Assertions.assertEquals(originalMessageSize, header.originalMessageSize());
		Assertions.assertEquals(flags, header.flags());
		Assertions.assertEquals(sessionId, header.sessionId());
	}

	@Test
	@DisplayName("Constructor rejects a segment smaller than 52 bytes")
	public void testRejectsTooSmallSegment() {
		var small = MemorySegment.ofArray(new byte[TransformHeader.STRUCTURE_SIZE - 1]);
		Assertions.assertThrows(IllegalArgumentException.class, () -> new TransformHeader(small));
	}

	@Test
	@DisplayName("Builder rejects a signature that is not exactly 16 bytes")
	public void testRejectsWrongSignatureLength() {
		var builder = TransformHeader.builder();
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.signature(new byte[15]));
	}

	@Test
	@DisplayName("Builder rejects a nonce that is not exactly 16 bytes")
	public void testRejectsWrongNonceLength() {
		var builder = TransformHeader.builder();
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.nonce(new byte[12]));
	}
}
