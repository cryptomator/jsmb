module org.cryptomator.jsmb {
	requires org.slf4j;
	requires static org.jetbrains.annotations;

	// Temporary dependency for providing a CMAC implementation
	// TODO: Replace (see: https://github.com/cryptomator/jsmb/issues/4)
	requires org.bouncycastle.provider;

	// provides java.security.Provider with org.cryptomator.jsmb.ntlmv2.LegacyCryptoProvider; // only required, if we want to find the provider by name

	exports org.cryptomator.jsmb.ntlmv2 to java.base; // allow java.security.Provider to access org.cryptomator.jsmb.ntlmv2.MD4
}