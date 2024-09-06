package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3">NTLM v2 Authentication</a>
 */
public class Authenticator {

	private static final String HMAC_MD5_ALGORITHM = "HmacMD5";

	public static byte[] NTOWFv2(String passwd, String user, String userDom) throws InvalidKeyException {
		byte[] md4Hash = md4(passwd.getBytes(StandardCharsets.UTF_16LE));
		return hmacMd5(md4Hash, (user.toUpperCase() + userDom).getBytes(StandardCharsets.UTF_16LE));
	}

	public static byte[] LMOWFv2(String passwd, String user, String userDom) throws InvalidKeyException {
		return NTOWFv2(passwd, user, userDom);
	}

	public static Response computeResponse(int negFlg, byte[] responseKeyNT, byte[] responseKeyLM,
										   byte[] serverChallenge, byte[] clientChallenge, byte[] time, AVPair serverName,
										   String user, String passwd) throws Exception {
		if (user.isEmpty() && passwd.isEmpty()) {
			// Special case for anonymous authentication
			return new Response(0, 0, 0, new byte[1], null);
		} else {
			byte[] responseVersion = new byte[]{1, 1}; // Responserversion, HiResponserversion
			byte[] temp = Bytes.concat(responseVersion, new byte[6], time, clientChallenge, new byte[4], serverName.segment().toArray(Layouts.BYTE), new byte[4]);
			byte[] ntProofStr = hmacMd5(responseKeyNT, Bytes.concat(serverChallenge, temp));
			byte[] ntChallengeResponse = Bytes.concat(ntProofStr, temp);
			byte[] lmChallengeResponse = Bytes.concat(hmacMd5(responseKeyLM, Bytes.concat(serverChallenge, clientChallenge)), clientChallenge);
			byte[] sessionBaseKey = hmacMd5(responseKeyNT, ntProofStr);
			return new Response(ntChallengeResponse.length, ntChallengeResponse.length, 0, lmChallengeResponse, sessionBaseKey);
		}
	}

	private static byte[] md4(byte[] input) {
		try {
			MessageDigest md = MessageDigest.getInstance(LegacyCryptoProvider.MD4, LegacyCryptoProvider.INSTANCE);
			return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("MD4 not found", e);
		}
	}

	private static byte[] hmacMd5(byte[] key, byte[] data) throws InvalidKeyException {
		try {
			Mac mac = Mac.getInstance(HMAC_MD5_ALGORITHM);
			SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_MD5_ALGORITHM);
			mac.init(keySpec);
			return mac.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("HmacMD5 not found", e);
		}
	}

	public record Response(int ntChallengeResponseLen, int ntChallengeResponseMaxLen, int ntChallengeResponseBufferOffset, byte[] lmChallengeResponse, byte[] sessionBaseKey) {
	}
}