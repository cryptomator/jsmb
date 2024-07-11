package org.cryptomator.jsmb.util;

import java.time.Instant;

/**
 * Utility class for converting between Java time and Windows file time.
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf">[MS-DTYP] FILETIME</a>
 */
public class WinFileTime {

	private static final Instant WIN_EPOCH = Instant.parse("1601-01-01T00:00:00Z");
	private static final long EPOCH_DIFF = Instant.EPOCH.toEpochMilli() - WIN_EPOCH.toEpochMilli();

	private WinFileTime() {
		// no-op
	}

	/**
	 * Converts Java epoch millis to Windows 100ns intervals.
	 * @param millis milliseconds since 1970-01-01 UTC
	 * @return 100-nanosecond intervals since 1601-01-01 UTC
	 */
	public static long fromMillis(long millis) {
		var epochAdjusted = EPOCH_DIFF + millis;
		return epochAdjusted * 10_000; // 1ms = 1000µs = 10000 x 100ns
	}

	public static long fromInstant(Instant instant) {
		return fromMillis(instant.toEpochMilli());
	}

	public static long now() {
		return fromInstant(Instant.now());
	}
}
