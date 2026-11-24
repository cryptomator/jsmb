package org.cryptomator.jsmb;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Server-level toggles passed to {@link Server#start(int, Set, Credentials)}. Each value is a
 * self-describing flag; an enabled flag is present in the set, a disabled flag is absent.
 * <p>
 * Not subject to configuration: a session is encrypted whenever the client negotiated a cipher, and requires
 * signing otherwise. There is no session that is neither encrypted nor signed.
 */
public enum Config {

	/**
	 * Refuse clients that didn't negotiate an encryption cipher. Without this flag, such clients get a
	 * session that is signed but not encrypted.
	 */
	REJECT_UNENCRYPTED_ACCESS,

	/**
	 * Log the derived session / signing / encryption / decryption / application keys at {@code INFO}
	 * for every successful {@code SESSION_SETUP}, formatted for Wireshark's SMB2 "Decryption keys"
	 * preference. <strong>Leaks secret key material by design</strong> — only enable when actively
	 * analyzing packet captures in deployments you control.
	 */
	DEBUG_ENCRYPTION;

	/**
	 * Secure defaults: encryption enforced ({@link #REJECT_UNENCRYPTED_ACCESS}); {@link #DEBUG_ENCRYPTION}
	 * deliberately omitted so key material stays out of the log. Immutable — pass it straight to
	 * {@link Server#start(int, Set, Credentials)} without copying.
	 */
	public static final Set<Config> DEFAULT = Set.of(REJECT_UNENCRYPTED_ACCESS);

	/**
	 * Builds an {@link EnumSet} of the supplied flags. Duplicate values are tolerated; an empty
	 * call returns an empty set.
	 *
	 * @param flags flags to enable
	 * @return a mutable set containing every distinct value in {@code flags}
	 */
	public static EnumSet<Config> create(Config... flags) {
		var set = EnumSet.noneOf(Config.class);
		Collections.addAll(set, flags);
		return set;
	}
}
