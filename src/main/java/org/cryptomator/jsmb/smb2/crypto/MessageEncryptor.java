package org.cryptomator.jsmb.smb2.crypto;

import org.cryptomator.jsmb.common.MalformedMessageException;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Encrypts and decrypts SMB 2 messages wrapped by an {@link TransformHeader}.
 * <p>
 * Supports AES-256-GCM, the only cipher currently negotiated by this server.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5cd64522-60b3-4f3e-a157-43a1e4bd76a4">3.1.4.3 Encrypting the Message</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/38abc82e-7fe2-4649-a3f1-63b7e10e11cc">3.2.5.1.3 Decrypting the Message</a>
 */
public class MessageEncryptor {

	private static final int GCM_TAG_BITS = 128;
	private static final int GCM_NONCE_BYTES = 12;

	private final SecureRandom secureRandom;

	public MessageEncryptor() {
		SecureRandom secureRandom;
		try {
			secureRandom = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support at least one strong SecureRandom implementation.", e);
		}
		this(secureRandom);

	}

	@VisibleForTesting
	MessageEncryptor(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	/**
	 * Wraps {@code plainMessage} in an SMB2 TRANSFORM_HEADER encrypted with AES-256-GCM under {@code key}.
	 *
	 * @return the on-the-wire bytes (52-byte TRANSFORM_HEADER followed by ciphertext of length {@code plainMessage.length})
	 */
	public byte[] encrypt(byte[] plainMessage, byte[] key, long sessionId) {
		byte[] nonce = new byte[GCM_NONCE_BYTES];
		secureRandom.nextBytes(nonce);
		return encrypt(plainMessage, key, sessionId, nonce);
	}

	@VisibleForTesting
	byte[] encrypt(byte[] plainMessage, byte[] key, long sessionId, byte[] nonce) {
		if (nonce.length != GCM_NONCE_BYTES) {
			throw new IllegalArgumentException("AES-GCM nonce must be " + GCM_NONCE_BYTES + " bytes");
		}
		byte[] noncePadded = Arrays.copyOf(nonce, 16);
		var headerSegment = MemorySegment.ofArray(new byte[TransformHeader.STRUCTURE_SIZE]);
		new TransformHeaderBuilder(headerSegment)
				.nonce(noncePadded)
				.originalMessageSize(plainMessage.length)
				.flags(TransformHeader.FLAG_ENCRYPTED)
				.sessionId(sessionId);
		byte[] aad = headerSegment.asSlice(20, 32).toArray(Layouts.BYTE);
		byte[] ciphertextWithTag = aesGcm(Cipher.ENCRYPT_MODE, plainMessage, aad, key, nonce);
		byte[] ciphertext = Arrays.copyOf(ciphertextWithTag, plainMessage.length);
		byte[] tag = Arrays.copyOfRange(ciphertextWithTag, plainMessage.length, ciphertextWithTag.length);
		new TransformHeaderBuilder(headerSegment).signature(tag);
		return Bytes.concat(headerSegment.toArray(Layouts.BYTE), ciphertext);
	}

	/**
	 * Decrypts an SMB2 TRANSFORM_HEADER + ciphertext buffer and returns the plaintext message.
	 *
	 * @throws MalformedMessageException if the buffer is too small for a TRANSFORM_HEADER, carries the
	 *         wrong protocol id, or if {@code OriginalMessageSize} doesn't match the ciphertext length
	 * @throws AEADBadTagException if the GCM authentication tag does not validate
	 */
	public byte[] decrypt(MemorySegment transformSegment, byte[] key) throws MalformedMessageException, AEADBadTagException {
		if (transformSegment.byteSize() < TransformHeader.STRUCTURE_SIZE) {
			throw new MalformedMessageException("Buffer smaller than TRANSFORM_HEADER");
		}
		var header = new TransformHeader(transformSegment.asSlice(0, TransformHeader.STRUCTURE_SIZE));
		if (header.protocolId() != TransformHeader.PROTOCOL_ID) {
			throw new MalformedMessageException("Not a SMB2 TRANSFORM_HEADER");
		}
		int ciphertextLength = header.originalMessageSize();
		if (ciphertextLength < 0 || transformSegment.byteSize() != TransformHeader.STRUCTURE_SIZE + ciphertextLength) {
			throw new MalformedMessageException("Encrypted payload length mismatch: header says " + ciphertextLength + ", buffer has " + (transformSegment.byteSize() - TransformHeader.STRUCTURE_SIZE));
		}
		byte[] nonce = Arrays.copyOf(header.nonce(), GCM_NONCE_BYTES);
		byte[] aad = transformSegment.asSlice(20, 32).toArray(Layouts.BYTE);
		byte[] tag = header.signature();
		byte[] ciphertext = transformSegment.asSlice(TransformHeader.STRUCTURE_SIZE, ciphertextLength).toArray(Layouts.BYTE);
		byte[] ciphertextWithTag = Bytes.concat(ciphertext, tag);
		try {
			return aesGcm(Cipher.DECRYPT_MODE, ciphertextWithTag, aad, key, nonce);
		} catch (IllegalStateException e) {
			if (e.getCause() instanceof AEADBadTagException bad) {
				throw bad;
			}
			throw e;
		}
	}

	private static byte[] aesGcm(int mode, byte[] input, byte[] aad, byte[] keyBytes, byte[] nonce) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(mode, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
			cipher.updateAAD(aad);
			return cipher.doFinal(input);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support AES/GCM/NoPadding", e);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Invalid key or algorithm parameter", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("AES-GCM " + (mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption") + " failed", e);
		}
	}
}
