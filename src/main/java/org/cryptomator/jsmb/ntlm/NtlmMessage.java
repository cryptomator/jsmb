package org.cryptomator.jsmb.ntlm;

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

	static NtlmMessage parse(MemorySegment segment) {
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
}
