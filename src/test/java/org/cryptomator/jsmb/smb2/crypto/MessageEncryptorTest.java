package org.cryptomator.jsmb.smb2.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.HexFormat;

class MessageEncryptorTest {

	@Test
	public void testRoundTrip() throws AEADBadTagException {
		byte[] key = HexFormat.of().parseHex("0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"); // 32-byte AES-256 key
		byte[] plaintext = "Hello, encrypted SMB2 world!".getBytes();
		long sessionId = 0xDEADBEEFCAFEBABEL;
		var encryptor = new MessageEncryptor();

		byte[] wire = encryptor.encrypt(plaintext, key, sessionId);

		Assertions.assertEquals(TransformHeader.STRUCTURE_SIZE + plaintext.length, wire.length);
		var header = new TransformHeader(MemorySegment.ofArray(wire).asSlice(0, TransformHeader.STRUCTURE_SIZE));
		Assertions.assertEquals(TransformHeader.PROTOCOL_ID, header.protocolId());
		Assertions.assertEquals(plaintext.length, header.originalMessageSize());
		Assertions.assertEquals(TransformHeader.FLAG_ENCRYPTED, header.flags());
		Assertions.assertEquals(sessionId, header.sessionId());

		byte[] decrypted = encryptor.decrypt(MemorySegment.ofArray(wire), key);
		Assertions.assertArrayEquals(plaintext, decrypted);
	}

	@Test
	public void testDeterministicEncryptWithFixedNonce() throws AEADBadTagException {
		byte[] key = new byte[32];
		Arrays.fill(key, (byte) 0x42);
		byte[] plaintext = new byte[64];
		Arrays.fill(plaintext, (byte) 0x7E);
		byte[] nonce = new byte[12];
		Arrays.fill(nonce, (byte) 0x01);
		long sessionId = 1L;
		var encryptor = new MessageEncryptor();

		byte[] wire1 = encryptor.encrypt(plaintext, key, sessionId, nonce);
		byte[] wire2 = encryptor.encrypt(plaintext, key, sessionId, nonce);

		Assertions.assertArrayEquals(wire1, wire2, "Same nonce must produce same ciphertext");
		Assertions.assertArrayEquals(plaintext, encryptor.decrypt(MemorySegment.ofArray(wire1), key));
	}

	@Test
	public void testTamperedCiphertextFailsAuth() {
		byte[] key = new byte[32];
		byte[] plaintext = "payload".getBytes();
		var encryptor = new MessageEncryptor();
		byte[] wire = encryptor.encrypt(plaintext, key, 0L);

		// flip one byte of the ciphertext
		wire[TransformHeader.STRUCTURE_SIZE] ^= 0x01;

		Assertions.assertThrows(AEADBadTagException.class, () -> encryptor.decrypt(MemorySegment.ofArray(wire), key));
	}

	@Test
	public void testTamperedAadFailsAuth() {
		byte[] key = new byte[32];
		byte[] plaintext = "payload".getBytes();
		var encryptor = new MessageEncryptor();
		byte[] wire = encryptor.encrypt(plaintext, key, 0L);

		// flip a bit in the Flags field (offset 42) — part of AAD
		wire[42] ^= 0x02;

		Assertions.assertThrows(AEADBadTagException.class, () -> encryptor.decrypt(MemorySegment.ofArray(wire), key));
	}

	@Test
	public void testDecryptRejectsWrongProtocolId() {
		byte[] key = new byte[32];
		byte[] wire = new byte[TransformHeader.STRUCTURE_SIZE];
		Assertions.assertThrows(IllegalArgumentException.class, () -> new MessageEncryptor().decrypt(MemorySegment.ofArray(wire), key));
	}

	@Test
	public void testDecryptRejectsSizeMismatch() {
		byte[] key = new byte[32];
		var encryptor = new MessageEncryptor();
		byte[] wire = encryptor.encrypt("ok".getBytes(), key, 0L);
		byte[] truncated = Arrays.copyOf(wire, wire.length - 1);
		Assertions.assertThrows(IllegalArgumentException.class, () -> encryptor.decrypt(MemorySegment.ofArray(truncated), key));
	}
}
