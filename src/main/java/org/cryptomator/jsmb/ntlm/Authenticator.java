package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.cryptomator.jsmb.ntlm.NegotiateFlags.isSet;

/**
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3">NTLM v2 Authentication</a>
 */
public class Authenticator {

	private static final String HMAC_MD5_ALGORITHM = "HmacMD5";

	private final byte[] responseKeyNT;
	private final byte[] responseKeyLM;
	private NtlmNegotiateMessage negotiateMessage;
	private NtlmChallengeMessage challengeMessage;

	private Authenticator(byte[] responseKeyNT, byte[] responseKeyLM) {
		this.responseKeyNT = responseKeyNT;
		this.responseKeyLM = responseKeyLM;
	}

	public static Authenticator create(String user, String passwd, String userDom) {
		byte[] responseKeyNT = NTOWFv2(passwd, user, userDom);
		byte[] responseKeyLM = LMOWFv2(passwd, user, userDom);
		return new Authenticator(responseKeyNT, responseKeyLM);
	}

	public @Nullable NtlmMessage process(NtlmMessage messageFromClient) throws AuthenticationFailedException {
		return switch (messageFromClient) {
			case NtlmNegotiateMessage msg -> createServerChallenge(msg);
			case NtlmChallengeMessage _ -> throw new UnsupportedOperationException("Did not expect NTLM challenge from client");
			case NtlmAuthenticateMessage msg -> {
				processClientChallenge(msg);
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
		this.negotiateMessage = negotiateMessage;
		// FIXME: this is a dummy implementation with hardcoded domain etc
		var targetInfo = List.of(
				AVPair.create(AVPair.MSV_AV_NB_COMPUTER_NAME, "jsmb"),
				AVPair.create(AVPair.MSV_AV_NB_DOMAIN_NAME, "localhost"),
				AVPair.create(AVPair.MSV_AV_DNS_COMPUTER_NAME, "jsmb"),
				AVPair.create(AVPair.MSV_AV_DNS_DOMAIN_NAME, "localhost"),
				AVPair.create(AVPair.MSV_AV_TIMESTAMP, Instant.now()),
				AVPair.create(AVPair.MSV_AV_EOL, MemorySegment.NULL)
		);
		int flags = negotiateMessage.negotiateFlags() & NtlmChallengeMessage.WANTED_NEG_FLAGS;
		flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NegotiateFlags.NTLMSSP_REQUEST_TARGET | NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
		this.challengeMessage = NtlmChallengeMessage.createChallenge("localhost", targetInfo, flags);
		return this.challengeMessage;
	}

	/**
	 * Server Receives an AUTHENTICATE_MESSAGE from the Client
	 * @param authenticateMessage message sent by the client to the server in response to the challenge message
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f9e6fbc4-a953-4f24-b229-ccdcc213b9ec">Server Receives an AUTHENTICATE_MESSAGE from the Client</a>
	 */
	private void processClientChallenge(NtlmAuthenticateMessage authenticateMessage) throws AuthenticationFailedException {
		if (challengeMessage == null || negotiateMessage == null) {
			throw new IllegalStateException("Received AUTHENTICATE_MESSAGE without prior CHALLENGE_MESSAGE");
		}
		if (authenticateMessage.ntChallengeResponseLen() < 24) {
			throw new AuthenticationFailedException(NTStatus.STATUS_NOT_SUPPORTED, "Only NTLMv2 is supported");
		}
		var response = ntlmV2Auth(challengeMessage, authenticateMessage);

		// If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit SessionBaseKey value. (source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d86303b5-b29e-4fb9-b119-77579c761370)
		var keyExchangeKey = response.sessionBaseKey;
		var messageMic = authenticateMessage.mic();
		authenticateMessage.setMic(new byte[16]); // erase

		// extended security (see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a92716d5-d164-4960-9e15-300f4eef44a8)
		var negFlg = challengeMessage.negotiateFlags();
		byte[] exportedSessionKey;
		if (isSet(negFlg, NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH) && (isSet(negFlg, NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN) || isSet(negFlg, NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL))) {
			exportedSessionKey = arc4(keyExchangeKey, authenticateMessage.encryptedRandomSessionKey());
		} else {
			exportedSessionKey = keyExchangeKey;
		}
		var mic = hmacMd5(exportedSessionKey, Bytes.concat(negotiateMessage.toByteArray(), challengeMessage.toByteArray(), authenticateMessage.toByteArray()));

		// if MIC is present, check if:
		var authenticateMessageFlags = authenticateMessage.ntlmV2Response().avPairs().get(AVPair.MSV_AV_FLAGS);
		if (authenticateMessageFlags != null && (authenticateMessageFlags.valueAsInt() & 0x2) != 0) {
			// The AV_PAIR structure with the MsvAvFlags field is present in the AUTHENTICATE_MESSAGE payload.
			// The MsvAvFlags field contains the AUTHENTICATE_MESSAGE bit.
			if (!Arrays.equals(mic, messageMic)) {
				throw new AuthenticationFailedException(NTStatus.STATUS_LOGON_FAILURE, "Message integrity check failed");
			}
		}

		// TODO: derive session keys and return ntlm session object
//		Set ClientSigningKey to SIGNKEY(NegFlg, ExportedSessionKey , "Client")
//		Set ServerSigningKey to SIGNKEY(NegFlg, ExportedSessionKey , "Server")
//		Set ClientSealingKey to SEALKEY(NegFlg, ExportedSessionKey , "Client")
//		Set ServerSealingKey to SEALKEY(NegFlg, ExportedSessionKey , "Server")
	}

	@VisibleForTesting
	AuthResponse ntlmV2Auth(NtlmChallengeMessage challengeMessage, NtlmAuthenticateMessage authenticateMessage) throws AuthenticationFailedException {
		var serverChallenge = challengeMessage.serverChallenge();

		if (authenticateMessage.userNameLen() == 0
				&& authenticateMessage.ntChallengeResponseLen() == 0
				&& (authenticateMessage.lmChallengeResponseLen() == 0 || Arrays.equals(new byte[]{0x00}, authenticateMessage.lmChallengeResponse()))) {
			throw new AuthenticationFailedException(NTStatus.STATUS_LOGON_FAILURE, "Anonymouse authentication disabled");
		}

		var ntlmV2Response = authenticateMessage.ntlmV2Response();
		byte[] challengeFromClient = ntlmV2Response.challengeFromClient();
		var time = ntlmV2Response.timestamp();
		var expectedResponse = computeResponse(responseKeyNT, responseKeyLM, serverChallenge, challengeFromClient, time, ntlmV2Response.avPairsSegment().toArray(Layouts.BYTE));

		if (!Arrays.equals(expectedResponse.ntChallengeResponse(), authenticateMessage.ntChallengeResponse())) {
			// TODO: spec recommends retrying with NIL domain to maximize comnpatibility
			throw new AuthenticationFailedException(NTStatus.STATUS_LOGON_FAILURE, "Invalid challenge response");
		}

		return expectedResponse;
	}

	public static byte[] NTOWFv2(String passwd, String user, String userDom) {
		byte[] md4Hash = md4(passwd.getBytes(StandardCharsets.UTF_16LE));
		return hmacMd5(md4Hash, (user.toUpperCase() + userDom).getBytes(StandardCharsets.UTF_16LE));
	}

	public static byte[] LMOWFv2(String passwd, String user, String userDom) {
		return NTOWFv2(passwd, user, userDom);
	}

	/**
	 * Calculates the keys used in NTLM v2 authentication.
	 * @param responseKeyNT result of NTOWF() function
	 * @param responseKeyLM result of LMOWF() function
	 * @param serverChallenge The 8-byte challenge message generated by the server
	 * @param clientChallenge The 8-byte challenge message generated by the client
	 * @param time The 8-byte little-endian time in GMT
	 * @param avPairs The {@link NtlmV2Response#avPairsSegment()}, including the EOL AVPair
	 * @return The expected NT and LM challenge responses and the session base key
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3">NTLM v2 Authentication</a>
	 */
	private static AuthResponse computeResponse(byte[] responseKeyNT, byte[] responseKeyLM, byte[] serverChallenge, byte[] clientChallenge, byte[] time, byte[] avPairs) {
		byte[] responseVersion = new byte[]{1, 1}; // Responserversion, HiResponserversion
		byte[] temp = Bytes.concat(responseVersion, new byte[6], time, clientChallenge, new byte[4], avPairs); // omitting the last 4 zero bytes mentioned in the linked documentation, as avPairs include EOL already
		byte[] ntProofStr = hmacMd5(responseKeyNT, Bytes.concat(serverChallenge, temp));
		byte[] ntChallengeResponse = Bytes.concat(ntProofStr, temp);
		byte[] lmChallengeResponse = Bytes.concat(hmacMd5(responseKeyLM, Bytes.concat(serverChallenge, clientChallenge)), clientChallenge);
		byte[] sessionBaseKey = hmacMd5(responseKeyNT, ntProofStr);
		return new AuthResponse(ntChallengeResponse, lmChallengeResponse, sessionBaseKey);
	}

	private static byte[] md4(byte[] input) {
		try {
			MessageDigest md = MessageDigest.getInstance(LegacyCryptoProvider.MD4, LegacyCryptoProvider.INSTANCE);
			return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("MD4 not found", e);
		}
	}

	private static byte[] hmacMd5(byte[] key, byte[] data) {
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

	private static byte[] arc4(byte[] key, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("ARCFOUR");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ARCFOUR"));
			return cipher.doFinal(data);
		} catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
			throw new IllegalStateException("ARCFOUR not found", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("ARCFOUR is a stream cipher, no blocks, no paddings", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Unsuitable key", e); // should not happen, as key is known to be 128 bit
		}
	}

	record AuthResponse(byte[] ntChallengeResponse, byte[] lmChallengeResponse, byte[] sessionBaseKey) {
	}
}