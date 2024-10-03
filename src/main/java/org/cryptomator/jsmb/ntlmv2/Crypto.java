package org.cryptomator.jsmb.ntlmv2;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Crypto {

	private static final String HMAC_MD5_ALGORITHM = "HmacMD5";
	private static final String ARCFOUR_ALGORITHM = "ARCFOUR";

	public static byte[] md4(byte[] input) {
		try {
			MessageDigest md = MessageDigest.getInstance(LegacyCryptoProvider.MD4, LegacyCryptoProvider.INSTANCE);
			return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("MD4 not found", e);
		}
	}

	public static byte[] hmacMd5(byte[] key, byte[] data) {
		try {
			Mac mac = Mac.getInstance(HMAC_MD5_ALGORITHM);
			SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_MD5_ALGORITHM);
			mac.init(keySpec);
			return mac.doFinal(data);
		} catch (InvalidKeyException e) {
			// RFC 2104, Section 3 states that HMAC keys may be of any length, as long as they are not empty
			throw new IllegalArgumentException("HMAC key is empty", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("HmacMD5 not found", e);
		}
	}

	public static byte[] arc4(byte[] key, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance(ARCFOUR_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ARCFOUR_ALGORITHM));
			return cipher.doFinal(data);
		} catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
			throw new IllegalStateException("ARCFOUR not found", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("ARCFOUR is a stream cipher, no blocks, no paddings", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Unsuitable key", e); // should not happen, as in the context of ntlmv2 authentication key is known to be 128 bit
		}
	}

}
