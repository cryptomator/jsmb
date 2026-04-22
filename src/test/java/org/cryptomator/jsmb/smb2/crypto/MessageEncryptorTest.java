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

	/**
	 * AES-128-GCM WRITE request test vector from the Microsoft OpenSpecifications blog
	 * <a href="https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-3-1-1-encryption-in-windows-10">
	 * "SMB 3.1.1 Encryption in Windows 10"</a>, Appendix A.1.
	 */
	@Test
	public void testMsSmb2Aes128GcmWriteVector() throws AEADBadTagException {
		var hex = HexFormat.of();
		byte[] encryptionKey = hex.parseHex("A2F5E80E5D59103034F32E52F698E5EC");
		byte[] nonce = hex.parseHex("C7D6822D269CAF48904C664C");
		long sessionId = 0x0000100000000025L;
		byte[] plaintext = hex.parseHex("""
						FE534D4240000100000000000900010008000000000000000500000000000000FFFE000001000000\
						25000000001000000000000000000000000000000000000031007000170000000000000000000000\
						0600000004000000010000000400000000000000000000007000000000000000536D623320656E63\
						72797074696F6E2074657374696E67\
						""");
		byte[] expectedTransformed = hex.parseHex("""
						FD534D42BD73D97D2BC9001BCAFAC0FDFF5FEEBCC7D6822D269CAF48904C664C0000000087000000\
						0000010025000000001000006ECDD2A7AFC7B47763057A041B8FD4DAFFE990B70C9E09D36C084E02\
						D14EF247F8BDE38ACF6256F8B1D3B56F77FBDEB312FEA5E92CBCC1ED8FB2EBBFAA75E49A4A394BB4\
						4576545567C24D4C014D47C9FBDFDAFD2C4F9B72F8D256452620A299F48E29E53D6B61D1C13A19E9\
						1AF013F00D17E3ABC2FC3D36C8C1B6B93973253852DBD442E46EE8\
						""");

		byte[] wire = new MessageEncryptor().encrypt(plaintext, encryptionKey, sessionId, nonce);

		Assertions.assertArrayEquals(expectedTransformed, wire);
		Assertions.assertArrayEquals(plaintext, new MessageEncryptor().decrypt(MemorySegment.ofArray(wire), encryptionKey));
	}
}
