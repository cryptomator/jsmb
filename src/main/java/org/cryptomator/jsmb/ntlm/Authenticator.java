package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3">NTLM v2 Authentication</a>
 */
public class Authenticator {

	private static final String HMAC_MD5_ALGORITHM = "HmacMD5";

	private final byte[] responseKeyNT;
	private final byte[] responseKeyLM;
	private int sequenceNumber = 0;

	private Authenticator(byte[] responseKeyNT, byte[] responseKeyLM) {
		this.responseKeyNT = responseKeyNT;
		this.responseKeyLM = responseKeyLM;
	}

	public static Authenticator create(String user, String passwd, String userDom) {
		byte[] responseKeyNT = NTOWFv2(passwd, user, userDom);
		byte[] responseKeyLM = LMOWFv2(passwd, user, userDom);
		return new Authenticator(responseKeyNT, responseKeyLM);
	}

	public @Nullable NtlmMessage process(NtlmMessage messageFromClient) {
		// TODO perform authentication: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654
		return switch (messageFromClient) {
			case NtlmNegotiateMessage negotiateMessage -> createServerChallenge(negotiateMessage);
			case NtlmChallengeMessage _ -> throw new UnsupportedOperationException("Did not expect NTLM challenge from client");
			case NtlmAuthenticateMessage authenticateMessage -> {
				processClientChallenge(authenticateMessage);
				yield null;
			}
		};
	}

	/**
	 * Server Receives a NEGOTIATE_MESSAGE from the Client
	 * @param negotiateMessage message sent by the client to the server to initiate NTLM authentication
	 * @return An NTLM CHALLENGE_MESSAGE
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/81d15e3e-3ac3-41f0-920d-846149f3a814">Server Receives a NEGOTIATE_MESSAGE from the Client</a>
	 */
	private NtlmMessage createServerChallenge(NtlmNegotiateMessage negotiateMessage) {
		// TODO: take negotiate message into account when producing the challenge
		// FIXME: this is a dummy implementation with hardcoded challenge etc
		var targetInfo = List.of(
				AVPair.create(AVPair.MSV_AV_NB_COMPUTER_NAME, "cryptomator"),
				AVPair.create(AVPair.MSV_AV_NB_DOMAIN_NAME, "local"),
				AVPair.create(AVPair.MSV_AV_DNS_COMPUTER_NAME, "local"),
				AVPair.create(AVPair.MSV_AV_DNS_DOMAIN_NAME, "local"),
				AVPair.create(AVPair.MSV_AV_TIMESTAMP, Instant.now()),
				AVPair.create(AVPair.MSV_AV_EOL, MemorySegment.NULL)
		);
		return NtlmChallengeMessage.createChallenge("target", "foobar00".getBytes(StandardCharsets.US_ASCII), targetInfo);
	}


	/**
	 * Server Receives an AUTHENTICATE_MESSAGE from the Client
	 * @param authenticateMessage message sent by the client to the server in response to the challenge message
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f9e6fbc4-a953-4f24-b229-ccdcc213b9ec">Server Receives an AUTHENTICATE_MESSAGE from the Client</a>
	 */
	private void processClientChallenge(NtlmAuthenticateMessage authenticateMessage) {
		// TODO compute session key
	}

	public static byte[] NTOWFv2(String passwd, String user, String userDom) {
		byte[] md4Hash = md4(passwd.getBytes(StandardCharsets.UTF_16LE));
		try {
			return hmacMd5(md4Hash, (user.toUpperCase() + userDom).getBytes(StandardCharsets.UTF_16LE));
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("key of length " + md4Hash.length + " inappropriate for HMAC-MD5", e);
		}
	}

	public static byte[] LMOWFv2(String passwd, String user, String userDom) {
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