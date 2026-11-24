package org.cryptomator.jsmb.smb2.crypto;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.PacketHeaderBuilder;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.smb2.negotiate.SigningCapabilities;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Signs SMB2 responses and verifies the signatures of SMB2 requests.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7">Signing the Message</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0">Signing An Outgoing Message</a>
 */
public class MessageSigner {

	private static final int NONCE_FLAG_IS_CLIENT = 0b0;
	private static final int NONCE_FLAG_IS_SERVER = 0b1;
	private static final int NONCE_FLAG_IS_CANCEL = 0b10;

	private static final int CMAC_LENGTH = 128;

	public PacketHeader sign(SMB2Message message, byte[] signingKey, Connection connection) {
		assert Objects.equals(connection.dialect, "3.1.1");
		return sign(message, signingKey, connection.signingAlgorithmId);
	}

	/**
	 * @implNote Requires dialect 3.1.1
	 */
	@VisibleForTesting
	PacketHeader sign(SMB2Message message, byte[] signingKey, @Nullable SigningCapabilities.Algorithm signingAlgorithm) {
		if (signingKey == null) {
			throw new IllegalStateException("Signing key not set");
		}
		var newHeader = message.header().copy().signature(new byte[16]); // zero out any existing signature
		newHeader.flags(message.header().flags() | SMB2Message.Flags.SIGNED);
		byte[] signature = computeSignature(newHeader, message, signingKey, signingAlgorithm, NONCE_FLAG_IS_SERVER);
		return newHeader.signature(signature).build();
	}

	/**
	 * Checks the signature of a request received from a client.
	 *
	 * @param message    the request exactly as received, i.e. its segment must not extend beyond the end of the message
	 * @param signingKey the key the client is expected to have signed the request with
	 * @param connection the connection the request has been received on
	 * @return {@code true} if the {@code Signature} field of the request's header matches the signature computed over the request
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5b570c0b-0854-4324-8fb5-d410692dde3e">Verifying an Incoming Message</a>
	 */
	public boolean verify(SMB2Message message, byte[] signingKey, Connection connection) {
		assert Objects.equals(connection.dialect, "3.1.1");
		return verify(message, signingKey, connection.signingAlgorithmId);
	}

	/**
	 * @implNote Requires dialect 3.1.1
	 */
	@VisibleForTesting
	boolean verify(SMB2Message message, byte[] signingKey, @Nullable SigningCapabilities.Algorithm signingAlgorithm) {
		var zeroedHeader = message.header().copy().signature(new byte[16]);
		byte[] expected = computeSignature(zeroedHeader, message, signingKey, signingAlgorithm, NONCE_FLAG_IS_CLIENT);
		return MessageDigest.isEqual(expected, message.header().signature()); // constant-time comparison
	}

	// signs the given header (whose Signature field must be zeroed) followed by the message's body
	private byte[] computeSignature(PacketHeaderBuilder header, SMB2Message message, byte[] signingKey, @Nullable SigningCapabilities.Algorithm signingAlgorithm, int senderNonceFlag) {
		byte[] data = Bytes.concat(header.segment().toArray(Layouts.BYTE), message.segment().toArray(Layouts.BYTE));
		if (signingAlgorithm == null || signingAlgorithm == SigningCapabilities.Algorithm.AES_CMAC) {
			return cmac(data, signingKey);
		} else if (signingAlgorithm == SigningCapabilities.Algorithm.AES_GMAC) {
			byte[] nonce = new byte[12];
			int flags = senderNonceFlag;
			if (message.header().command() == Command.CANCEL.value()) {
				flags |= NONCE_FLAG_IS_CANCEL;
			}
			ByteBuffer.wrap(nonce) //
					.order(ByteOrder.LITTLE_ENDIAN) //
					.putLong(0, message.header().messageId()) //
					.putInt(8, flags);
			return gmac(data, nonce, signingKey);
		} else {
			throw new UnsupportedOperationException("Unsupported algorithm: " + signingAlgorithm);
		}
	}

	@VisibleForTesting
	byte[] gmac(byte[] data, byte[] nonce, byte[] signingKeyBytes) {
		try {
			Key signingKey = new SecretKeySpec(signingKeyBytes, "AES");
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, signingKey, spec);
			cipher.updateAAD(data);
			return cipher.doFinal(new byte[0]); // empty, as we just want the tag
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support AES/GCM/NoPadding", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new AssertionError("Block size or padding irrelevant when encrypting with GCM", e);
		} catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key or algorithm parameter", e);
		}
	}

	@VisibleForTesting
	byte[] cmac(byte[] data, byte[] signingKeyBytes) {
		var mac = new CMac(AESEngine.newInstance(), CMAC_LENGTH);
		var params = new KeyParameter(signingKeyBytes);
		mac.init(params);
		mac.update(data, 0, data.length);

		var result = new byte[CMAC_LENGTH / 8];
		mac.doFinal(result, 0);
		return result;
	}
}
