package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

/**
 * The CHALLENGE_MESSAGE defines the NTLM challenge message that the server sends to the client.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786>CHALLENGE_MESSAGE</a>
 */
record NtlmChallengeMessage(MemorySegment segment) implements NtlmMessage {

	private static final int CHALLENGE_LENGTH = 8;

	public static final int WANTED_NEG_FLAGS = NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH
			| NegotiateFlags.NTLMSSP_NEGOTIATE_128
			| NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION
			| NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO
			| NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
			| NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
			| NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN
			| NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL
			| NegotiateFlags.NTLMSSP_REQUEST_TARGET
			| NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE;
	public static final int MESSAGE_TYPE = 0x00000002;

	public static NtlmChallengeMessage createChallenge(String targetName, List<AVPair> targetInfo, int flags) {
		if (targetInfo.getLast().avId() != AVPair.MSV_AV_EOL) {
			throw new IllegalArgumentException("Last AV pair must be EOL.");
		}
		byte[] targetNameBytes = targetName.getBytes(StandardCharsets.UTF_16LE);
		byte[] targetInfoBytes = targetInfo.stream().map(AVPair::segment).reduce(MemorySegment.NULL, MemorySegments::concat).toArray(Layouts.BYTE);

		MemorySegment segment = MemorySegment.ofArray(new byte[56 + targetNameBytes.length + targetInfoBytes.length]);
		segment.copyFrom(MemorySegment.ofArray(NtlmMessage.SIGNATURE)); // Signature
		segment.set(Layouts.LE_INT32, 8, MESSAGE_TYPE); // MessageType

		// TargetNameFields:
		segment.set(Layouts.LE_UINT16, 12, (char) targetNameBytes.length); // TargetNameLen
		segment.set(Layouts.LE_UINT16, 14, (char) targetNameBytes.length); // TargetNameMaxLen
		segment.set(Layouts.LE_INT32, 16, 56); // TargetNameBufferOffset

		// Flags
		segment.set(Layouts.LE_INT32, 20, flags);

		// ServerChallenge:
		try {
			byte[] serverChallenge = new byte[CHALLENGE_LENGTH];
			SecureRandom.getInstanceStrong().nextBytes(serverChallenge);
			segment.asSlice(24, 8).copyFrom(MemorySegment.ofArray(serverChallenge));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SecureRandom not found", e);
		}

		// TargetInfoFields:
		segment.set(Layouts.LE_UINT16, 40, (char) targetInfoBytes.length); // TargetInfoLen
		segment.set(Layouts.LE_UINT16, 42, (char) targetInfoBytes.length); // TargetInfoMaxLen
		segment.set(Layouts.LE_INT32, 44, 56 + targetNameBytes.length); // TargetInfoBufferOffset

		// Version (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175):
		segment.set(Layouts.BYTE, 48, (byte) 6); // ProductMajorVersion TODO
		segment.set(Layouts.BYTE, 49, (byte) 1); // ProductMinorVersion TODO
		segment.set(Layouts.LE_UINT16, 50, (char) 7600); // ProductBuild TODO
		segment.set(Layouts.BYTE, 55, NtlmMessage.NTLMSSP_REVISION_W2K3); // NTLMRevisionCurrent

		// Payload:
		segment.asSlice(56, targetNameBytes.length).copyFrom(MemorySegment.ofArray(targetNameBytes)); // TargetName
		segment.asSlice(56 + targetNameBytes.length, targetInfoBytes.length).copyFrom(MemorySegment.ofArray(targetInfoBytes)); // TargetInfo

		return new NtlmChallengeMessage(segment);
	}

	public byte[] serverChallenge() {
		return segment.asSlice(24, 8).toArray(Layouts.BYTE);
	}

	public int negotiateFlags() {
		return segment.get(Layouts.LE_INT32, 20);
	}

}
