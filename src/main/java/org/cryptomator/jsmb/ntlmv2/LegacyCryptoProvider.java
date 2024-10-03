package org.cryptomator.jsmb.ntlmv2;

import java.security.Provider;

public final class LegacyCryptoProvider extends Provider {

	public static final String NAME = "NTLMLegacyCryptoProvider";

	public static final String MD4 = "MD4";

	public static final Provider INSTANCE = new LegacyCryptoProvider();

	public LegacyCryptoProvider() {
		super(NAME, "1.0","Provides legacy NTLM crypto algorithms such as MD4");
		// putService(Service);
		put("MessageDigest." + MD4, MD4.class.getName());
	}
}
