package org.cryptomator.jsmb.smb2;

import java.util.BitSet;

/**
 * The set of MessageIds a client may use on a connection, which doubles as the count of credits it holds: one per MessageId that is still available.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dec8e905-9477-4c3f-bc64-b18d97c9f905">Algorithm for Handling Available Message Sequence Numbers by the Server</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/2e366edb-b006-47e7-aa94-ef6f71043ced">Algorithm for the Granting of Credits</a>
 */
public class CommandSequenceWindow {

	/**
	 * The most credits a client may hold at a time.
	 */
	public static final int MAX_CREDITS = 8192;

	// Bounds the bookkeeping for a client that keeps skipping the lowest MessageId: the window stops growing until that one got used.
	private static final int MAX_SPAN = 2 * MAX_CREDITS;

	// The window spans [low, high). The bit at index i tells whether MessageId low + i got used already; low itself is always unused, unless the window is empty.
	private long low = 0;
	private long high = 1;
	private BitSet used = new BitSet();

	/**
	 * Takes consecutive MessageIds out of the window, as done for an incoming request.
	 *
	 * @param messageId the first MessageId, i.e. the one in the request's header
	 * @param count     how many MessageIds the request consumes, which is its credit charge
	 * @return {@code false} if any of the MessageIds is not available, in which case the window is left unchanged
	 */
	public boolean consume(long messageId, int count) {
		// MessageIds beyond Long.MAX_VALUE show up as negative numbers and are refused, which is as good as terminating the connection on a wrap-around of the 64-bit sequence
		if (count < 1 || messageId < low || messageId > high - count) {
			return false;
		}
		int from = (int) (messageId - low);
		int firstUsed = used.nextSetBit(from);
		if (firstUsed >= 0 && firstUsed < from + count) {
			return false;
		}
		used.set(from, from + count);
		int leadingUsed = used.nextClearBit(0);
		if (leadingUsed > 0) {
			used = used.get(leadingUsed, Math.max(leadingUsed, used.length()));
			low += leadingUsed;
		}
		return true;
	}

	/**
	 * Extends the window, as done when responding to a request.
	 * <p>
	 * As long as the caller asks for at least as many credits as the request consumed, the client never ends up without any.
	 *
	 * @param requested the number of credits to grant if the limits allow for it
	 * @return the number of credits actually granted, to be put into the response's CreditResponse field
	 */
	public int grant(int requested) {
		long limit = Math.min(MAX_CREDITS - available(), MAX_SPAN - (high - low));
		int granted = (int) Math.max(0, Math.min(requested, limit));
		high += granted;
		return granted;
	}

	/**
	 * @return the number of MessageIds available to the client, i.e. the credits it holds
	 */
	public int available() {
		return (int) (high - low) - used.cardinality();
	}
}
