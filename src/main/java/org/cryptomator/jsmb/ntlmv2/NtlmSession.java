package org.cryptomator.jsmb.ntlmv2;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.util.Bytes;

import java.lang.foreign.MemorySegment;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.cryptomator.jsmb.ntlmv2.NegotiateFlags.isSet;

public sealed interface NtlmSession permits NtlmSession.Initial, NtlmSession.AwaitingAuthentication, NtlmSession.Authenticated {

	static NtlmSession.Initial create() {
		return new Initial();
	}

	/**
	 * The initial state of an NTLM session before receiving any messages from the client.
	 *
	 * After {@link #negotiate(byte[]) receiving a NEGOTIATE_MESSAGE}, a server challenge is created and the session transitions to {@link AwaitingAuthentication}.
	 */
	final class Initial implements NtlmSession {

		/**
		 * Server Receives a NEGOTIATE_MESSAGE from the Client
		 * @param ntlmMessage The NEGOTIATE_MESSAGE sent by the client to the server to initiate NTLM authentication
		 * @return An NTLM CHALLENGE_MESSAGE
		 * @throws IllegalArgumentException if the message is not a NEGOTIATE_MESSAGE
		 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/81d15e3e-3ac3-41f0-920d-846149f3a814">Server Receives a NEGOTIATE_MESSAGE from the Client</a>
		 */
		public AwaitingAuthentication negotiate(byte[] ntlmMessage) throws IllegalArgumentException {
			var parsedMessage = NtlmMessage.parse(MemorySegment.ofArray(ntlmMessage));
			if (!(parsedMessage instanceof NtlmNegotiateMessage negotiateMessage)) {
				throw new IllegalArgumentException("Expected NEGOTIATE_MESSAGE, got " + parsedMessage);
			}

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
			var challengeMessage = NtlmChallengeMessage.createChallenge("localhost", targetInfo, flags);
			return new AwaitingAuthentication(negotiateMessage, challengeMessage);
		}

	}

	/**
	 * The state of an NTLM session after sending a CHALLENGE_MESSAGE to the client.
	 *
	 * After completing {@link #authenticate(byte[], String, String, String) authentication}, the session transitions to {@link Authenticated}.
	 *
	 * @param negotiateMessage The NEGOTIATE_MESSAGE sent by the client to the server to initiate NTLM authentication
	 * @param challengeMessage The CHALLENGE_MESSAGE sent by the server to the client in response to the NEGOTIATE_MESSAGE
	 */
	record AwaitingAuthentication(NtlmNegotiateMessage negotiateMessage, NtlmChallengeMessage challengeMessage) implements NtlmSession {

		/**
		 * The CHALLENGE_MESSAGE to be sent to the client in response to a prior NEGOTIATE_MESSAGE
		 * @return encoded CHALLENGE_MESSAGE
		 */
		public byte[] serverChallenge() {
			return challengeMessage.toByteArray();
		}

		/**
		 * Server Receives an AUTHENTICATE_MESSAGE from the Client
		 * @param gssToken The AUTHENTICATE_MESSAGE message sent by the client to the server in response to the CHALLENGE_MESSAGE
		 * @param user The username
		 * @param password The password
		 * @param domain The domain
		 * @return An authenticated NTLM session
		 * @throws IllegalArgumentException if the message is not an AUTHENTICATE_MESSAGE
		 * @throws AuthenticationFailedException if the authentication failed
		 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f9e6fbc4-a953-4f24-b229-ccdcc213b9ec">Server Receives an AUTHENTICATE_MESSAGE from the Client</a>
		 */
		public Authenticated authenticate(byte[] gssToken, String user, String password, String domain) throws IllegalArgumentException, AuthenticationFailedException {
			var msg = NtlmMessage.parse(MemorySegment.ofArray(gssToken));
			if (!(msg instanceof NtlmAuthenticateMessage authenticateMessage)) {
				throw new IllegalArgumentException("Expected AUTHENTICATE_MESSAGE, got " + msg);
			}

			if (authenticateMessage.ntChallengeResponseLen() < 24) {
				throw new AuthenticationFailedException(NTStatus.STATUS_NOT_SUPPORTED, "Only NTLMv2 is supported");
			}
			var response = Authenticator.ntlmV2Auth(challengeMessage, authenticateMessage, user, password, domain);

			// If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit SessionBaseKey value. (source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d86303b5-b29e-4fb9-b119-77579c761370)
			var keyExchangeKey = response.sessionBaseKey();
			var messageMic = authenticateMessage.mic();
			authenticateMessage.setMic(new byte[16]); // erase

			// extended security (see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a92716d5-d164-4960-9e15-300f4eef44a8)
			var negFlg = challengeMessage.negotiateFlags();
			byte[] exportedSessionKey;
			if (isSet(negFlg, NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH) && (isSet(negFlg, NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN) || isSet(negFlg, NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL))) {
				exportedSessionKey = Crypto.arc4(keyExchangeKey, authenticateMessage.encryptedRandomSessionKey());
			} else {
				exportedSessionKey = keyExchangeKey;
			}
			var mic = Crypto.hmacMd5(exportedSessionKey, Bytes.concat(negotiateMessage.toByteArray(), challengeMessage.toByteArray(), authenticateMessage.toByteArray()));

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
			return new Authenticated();
		}

	}

	final  class Authenticated implements NtlmSession {
	}
}
