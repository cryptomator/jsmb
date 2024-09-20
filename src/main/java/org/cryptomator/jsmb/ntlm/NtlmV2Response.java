package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.List;

public record NtlmV2Response(MemorySegment segment) {

	byte[] challengeResponse() {
		return segment.asSlice(0, 16).toArray(Layouts.BYTE);
	}

	byte respType() {
		return segment.get(Layouts.BYTE, 16);
	}

	byte hiRespType() {
		return segment.get(Layouts.BYTE, 17);
	}

	long timestamp() {
		return segment.get(Layouts.LE_INT64, 24);
	}

	byte[] challengeFromClient() {
		return segment.asSlice(32, 8).toArray(Layouts.BYTE);
	}

	List<AVPair> avPairs() {
		return AVPair.parse(segment.asSlice(44));
	}

}
