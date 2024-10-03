package org.cryptomator.jsmb.ntlmv2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;

public sealed interface NtlmMessage permits NtlmNegotiateMessage, NtlmChallengeMessage, NtlmAuthenticateMessage {

	byte[] SIGNATURE = new byte[] { (byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P', 0 };
	byte NTLMSSP_REVISION_W2K3 = 0x0F;

	MemorySegment segment();

	default byte[] signature() {
		return segment().asSlice(0, 8).toArray(Layouts.BYTE);
	}

	default int messageType() {
		return segment().get(Layouts.LE_INT32, 8);
	}

	/**
	 * Parses an NTLM message from a memory segment.
	 * @param segment the memory segment containing the NTLM message
	 * @return the parsed NTLM message
	 * @throws IllegalArgumentException in case the memory segment does not contain an NTLM message
	 */
	static NtlmMessage parse(MemorySegment segment) throws IllegalArgumentException {
		var signature = segment.asSlice(0, SIGNATURE.length).toArray(Layouts.BYTE);
		if (!Arrays.equals(SIGNATURE, 0, SIGNATURE.length, signature, 0, SIGNATURE.length)) {
			throw new IllegalArgumentException("Not an NTLM message");
		}
		var messageType = segment.get(Layouts.LE_INT32, 8);
		return switch (messageType) {
			case NtlmNegotiateMessage.MESSAGE_TYPE -> new NtlmNegotiateMessage(segment);
			case NtlmChallengeMessage.MESSAGE_TYPE -> new NtlmChallengeMessage(segment);
			case NtlmAuthenticateMessage.MESSAGE_TYPE -> new NtlmAuthenticateMessage(segment);
			default -> throw new IllegalArgumentException("Unknown NTLM message type: " + messageType);
		};
	}

	default byte[] toByteArray() {
		return segment().toArray(Layouts.BYTE);
	}
}
