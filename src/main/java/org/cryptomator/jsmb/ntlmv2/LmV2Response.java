package org.cryptomator.jsmb.ntlmv2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * The LMv2_RESPONSE structure defines the NTLM v2 authentication transported in {@link NtlmAuthenticateMessage#lmChallengeResponse()}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/8659238f-f5a9-44ad-8ee7-f37d3a172e56">LMv2_RESPONSE</a>
 */
record LmV2Response(MemorySegment segment) {

	byte[] challengeResponse() {
		return segment.asSlice(0, 16).toArray(Layouts.BYTE);
	}

	byte[] challengeFromClient() {
		return segment.asSlice(16, 8).toArray(Layouts.BYTE);
	}

}
