package org.cryptomator.jsmb.smb2.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class TransformHeaderTest {

	@Test
	public void testRoundTrip() {
		byte[] signature = new byte[16];
		byte[] nonce = new byte[16];
		for (int i = 0; i < 16; i++) {
			signature[i] = (byte) (0xA0 + i);
			nonce[i] = (byte) (0x10 + i);
		}
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
	public void testRejectsTooSmallSegment() {
		var small = MemorySegment.ofArray(new byte[TransformHeader.STRUCTURE_SIZE - 1]);
		Assertions.assertThrows(IllegalArgumentException.class, () -> new TransformHeader(small));
	}

	@Test
	public void testRejectsWrongSignatureLength() {
		var builder = TransformHeader.builder();
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.signature(new byte[15]));
	}

	@Test
	public void testRejectsWrongNonceLength() {
		var builder = TransformHeader.builder();
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.nonce(new byte[12]));
	}
}
