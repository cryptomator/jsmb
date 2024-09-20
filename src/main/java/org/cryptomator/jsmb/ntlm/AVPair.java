package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;
import org.cryptomator.jsmb.util.WinFileTime;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an AV pair as defined in the NTLM authentication protocol.
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e">AV_PAIR</a>
 */
public record AVPair(MemorySegment segment) {

	public static final int MSV_AV_EOL = 0x0000;
	public static final int MSV_AV_NB_COMPUTER_NAME = 0x0001;
	public static final int MSV_AV_NB_DOMAIN_NAME = 0x0002;
	public static final int MSV_AV_DNS_COMPUTER_NAME = 0x0003;
	public static final int MSV_AV_DNS_DOMAIN_NAME = 0x0004;
	public static final int MSV_AV_DNS_TREE_NAME = 0x0005;
	public static final int MSV_AV_FLAGS = 0x0006;
	public static final int MSV_AV_TIMESTAMP = 0x0007;
	public static final int MSV_AV_SINGLE_HOST = 0x0008;
	public static final int MSV_AV_TARGET_NAME = 0x0009;
	public static final int MSV_AV_CHANNEL_BINDINGS = 0x000A;

	public AVPair {
		if (segment.byteSize() < 4) {
			throw new IllegalArgumentException("Segment too small for AVPair");
		}
	}

	/**
	 * Convenience factory method for creating an AV pair with a string value.
	 * @param avId The AV pair ID.
	 * @param value The value.
	 * @return A new AV pair.
	 */
	public static AVPair create(int avId, String value) {
		return create(avId, MemorySegment.ofBuffer(StandardCharsets.UTF_16LE.encode(value)));
	}

	/**
	 * Convenience factory method for creating an AV pair with a timestamp value.
	 * @param avId The AV pair ID.
	 * @param value The value.
	 * @return A new AV pair.
	 */
	public static AVPair create(int avId, Instant value) {
		var fileTime = WinFileTime.fromInstant(value);
		var segment = MemorySegment.ofArray(new byte[Long.BYTES]);
		segment.set(Layouts.LE_INT64, 0, fileTime);
		return create(avId, segment);
	}

	public static AVPair create(int avId, MemorySegment value) {
		var header = MemorySegment.ofArray(new byte[4]);
		header.set(Layouts.LE_UINT16, 0, (char) avId);
		header.set(Layouts.LE_UINT16, 2, (char) value.byteSize());
		var combined = MemorySegments.concat(header, value);
		return new AVPair(combined);
	}

	public static List<AVPair> parse(MemorySegment segment) {
		var result = new ArrayList<AVPair>();
		parse(segment, result);
		return result;
	}

	private static void parse(MemorySegment segment, List<AVPair> result) {
		if (segment.byteSize() < 4) {
			throw new IllegalArgumentException("Segment too small for AVPair");
		}
		char avId = segment.get(Layouts.LE_UINT16, 0);
		char avLen = segment.get(Layouts.LE_UINT16, 2);
		var avPairSegment = segment.asSlice(0, 4 + avLen);
		result.add(new AVPair(avPairSegment));
		if (avId != MSV_AV_EOL) {
			parse(segment.asSlice(avPairSegment.byteSize()), result);
		}
	}

	public char avId() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public char avLen() {
		return segment.get(Layouts.LE_UINT16, 2);
	}

	public MemorySegment value() {
		return segment.asSlice(4, avLen());
	}
}
