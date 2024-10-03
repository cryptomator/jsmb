package org.cryptomator.jsmb.ntlmv2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.Collections;
import java.util.SequencedMap;

/**
 * The NTLMv2_CLIENT_CHALLENGE structure defines the client challenge transported in {@link NtlmAuthenticateMessage#ntChallengeResponse()}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80">NTLMv2_RESPONSE</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b">NTLMv2_CLIENT_CHALLENGE</a>
 */
record NtlmV2Response(MemorySegment segment) {

	/**
	 * Response corresponds to the NTProofStr variable
	 */
	byte[] challengeResponse() {
		return segment.asSlice(0, 16).toArray(Layouts.BYTE);
	}

	byte respType() {
		return segment.get(Layouts.BYTE, 16);
	}

	byte hiRespType() {
		return segment.get(Layouts.BYTE, 17);
	}

	byte[] timestamp() {
		return segment.asSlice(24, 8).toArray(Layouts.BYTE);
	}

	/**
	 * ChallengeFromClient corresponds to the temp variable
	 */
	byte[] challengeFromClient() {
		return segment.asSlice(32, 8).toArray(Layouts.BYTE);
	}

	MemorySegment avPairsSegment() {
		return segment.asSlice(44);
	}

	SequencedMap<Character, AVPair> avPairs() {
		return Collections.unmodifiableSequencedMap(AVPair.parse(avPairsSegment()));
	}

}
