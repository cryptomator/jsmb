package org.cryptomator.jsmb.smb2.crypto;

import org.cryptomator.jsmb.ntlmv2.NtlmSession;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.smb2.Session;
import org.cryptomator.jsmb.smb2.negotiate.SigningCapabilities;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Signs an SMB2 message.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7">Signing the Message</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0">Signing An Outgoing Message</a>
 */
public class MessageSigner {

	private static final int NONCE_FLAG_IS_SERVER = 0b1;
	private static final int NONCE_FLAG_IS_CANCEL = 0b10;

	private final Session session;

	public MessageSigner(Session session) {
		this.session = session;
	}

	public PacketHeader sign(SMB2Message message) {
		if (session.signingKey == null) {
			throw new IllegalStateException("Signing key not set");
		}
		var newHeader = message.header().copy().signature(new byte[16]); // zero out any existing signature
		//newHeader.flags(message.header().flags() | SMB2Message.Flags.SIGNED);

		if (session.connection.signingAlgorithmId == SigningCapabilities.AES_GMAC) {
			byte[] nonce = new byte[12];
			int flags = NONCE_FLAG_IS_SERVER;
			if (message.header().command() == Command.CANCEL.value()) {
				flags |= NONCE_FLAG_IS_CANCEL;
			}
			ByteBuffer.wrap(nonce) //
					.putLong(0, message.header().messageId()) //
					.putInt(8, flags);
			byte[] data = Bytes.concat(newHeader.segment().toArray(Layouts.BYTE), message.segment().toArray(Layouts.BYTE), new byte[20]); // FIXME
			byte[] signature = gmac(data, nonce, session.signingKey);
			return newHeader.signature(signature).build();
		} else {
			throw new UnsupportedOperationException("Only GMAC implemented");
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

}
