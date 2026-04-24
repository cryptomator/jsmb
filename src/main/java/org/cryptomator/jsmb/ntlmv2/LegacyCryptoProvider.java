package org.cryptomator.jsmb.ntlmv2;

import java.security.Provider;

/**
 * JCE {@link Provider} supplying the legacy hash algorithms NTLMv2 still needs (in particular {@code MD4}),
 * which the stock JDK providers no longer expose. Registered at runtime; not a default-installed provider.
 */
public final class LegacyCryptoProvider extends Provider {

	/** Provider name as seen by JCA lookups. */
	public static final String NAME = "NTLMLegacyCryptoProvider";

	/** Algorithm name of the MD4 {@link java.security.MessageDigest} this provider contributes. */
	public static final String MD4 = "MD4";

	/** Shared instance — usable both as a service-loader-style singleton and for direct registration. */
	public static final Provider INSTANCE = new LegacyCryptoProvider();

	/**
	 * Constructs a new instance. Prefer {@link #INSTANCE} — this constructor is only public because
	 * {@code java.security.Provider} subclasses must be instantiable by the JCA infrastructure.
	 */
	public LegacyCryptoProvider() {
		super(NAME, "1.0","Provides legacy NTLM crypto algorithms such as MD4");
		// putService(Service);
		put("MessageDigest." + MD4, MD4.class.getName());
	}
}
