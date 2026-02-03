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

	NtlmV2Response {
		if (!isV2(segment)) {
			throw new IllegalArgumentException("Invalid segment version or format");
		}
	}

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

	/**
	 * Indicates whether the given <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce">{@code NtChallengeResponse}</a>
	 * segment is an {@link NtlmV2Response NtlmV2Response.}
	 *
	 * @param segment A segment containing an {@code NtChallengeResponse:} Either {@code NtlmResponse (NTLM_RESPONSE)} or {@code NtlmV2Response (NTLMv2_RESPONSE.)}
	 * @return true if the structure of the given response segment is congruent with {@code NTLMv2;} false otherwise.</br>
	 * The result of calling this method with a malformed response segment is undefined.
	 * @throws IllegalArgumentException if the given response segement is empty and therefore can't possibly represent a valid {@code NtChallengeResponse.}
	 * @implNote The NTLM specification does not make any provisions about determining the NTLM version <i>during</i> authentication,
	 * opting instead to note that the NTLM version must be configured <i>beforehand.</i></br>
	 * Example from <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3">3.3.2 NTLM v2 Authentication:</a>
	 * <blockquote>
	 * <p><b>Note</b> The NTLM authentication version is not negotiated by the protocol. It MUST be configured on both the client and the server prior to authentication.</p>
	 * </blockquote>
	 * In practice this approach is not feasible for many implementations. The heuristic implemented by this method decides between the two possible types
	 * <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b88739c6-1266-49f7-9d22-b13923bd8d66">NtlmResponse (NTLM_RESPONSE)</a>
	 * or <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80">NtlmV2Response (NTLMv2_RESPONSE)</a>
	 * based on the length of the response segment:</br>
	 * V1 segments are always {@code 24 bytes} long, while v2 segments are always longer.
	 * @see <a href="https://github.com/heimdal/heimdal/blob/7510cc5ba27d5e6c01ad09692b8aa62f9dd0eab9/kdc/digest.c#L1226-L1227">An implementation of this heuristic in Heimdal (used by Samba.)</a>
	 * @see <a href="https://github.com/wireshark/wireshark/blob/bae104a85598e6987ae1a3f2724fc6f80f838a32/epan/dissectors/packet-ntlmssp.c#L987-L1001">An implementation of this heuristic in Wireshark.</a>
	 */
	static boolean isV2(MemorySegment segment) {
		if (segment.byteSize() == 0) {
			throw new IllegalArgumentException("NTLM: NT required (Empty NtChallengeResponse segment)");
		}
		return segment.byteSize() > 24;
	}
}
