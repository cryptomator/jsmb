package org.cryptomator.jsmb;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Server-level toggles passed to {@link Server#start(int, Set, Credentials)}. Each value is a
 * self-describing flag; an enabled flag is present in the set, a disabled flag is absent.
 */
public enum Config {

	/**
	 * Negotiate SMB2 encryption on every session and wrap responses in a {@code TRANSFORM_HEADER}.
	 */
	ENCRYPT_DATA,

	/**
	 * Refuse clients that don't advertise {@code SMB2_GLOBAL_CAP_ENCRYPTION}. Typically paired with
	 * {@link #ENCRYPT_DATA}; without it, a downgrading client could connect in plaintext.
	 */
	REJECT_UNENCRYPTED_ACCESS,

	/**
	 * Advertise {@code SIGNING_REQUIRED} in the {@code NEGOTIATE} response. Signing is superseded by
	 * AEAD when {@link #ENCRYPT_DATA} is active, but still meaningful for unencrypted sessions.
	 */
	REQUIRE_MESSAGE_SIGNING,

	/**
	 * Log the derived session / signing / encryption / decryption / application keys at {@code INFO}
	 * for every successful {@code SESSION_SETUP}, formatted for Wireshark's SMB2 "Decryption keys"
	 * preference. <strong>Leaks secret key material by design</strong> — only enable when actively
	 * analyzing packet captures in deployments you control.
	 */
	DEBUG_ENCRYPTION;

	/**
	 * Secure defaults: encryption enforced ({@link #ENCRYPT_DATA}, {@link #REJECT_UNENCRYPTED_ACCESS})
	 * and signing required ({@link #REQUIRE_MESSAGE_SIGNING}); {@link #DEBUG_ENCRYPTION} deliberately
	 * omitted so key material stays out of the log. Immutable — pass it straight to
	 * {@link Server#start(int, Set, Credentials)} without copying.
	 */
	public static final Set<Config> DEFAULT = Set.of(ENCRYPT_DATA, REJECT_UNENCRYPTED_ACCESS, REQUIRE_MESSAGE_SIGNING);

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
