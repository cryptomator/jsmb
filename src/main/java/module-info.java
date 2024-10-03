module org.cryptomator.jsmb {
	requires org.slf4j;
	requires static org.jetbrains.annotations;

	// provides java.security.Provider with org.cryptomator.jsmb.ntlmv2.LegacyCryptoProvider; // only required, if we want to find the provider by name

	exports org.cryptomator.jsmb.ntlmv2 to java.base; // allow java.security.Provider to access org.cryptomator.jsmb.ntlmv2.MD4
}