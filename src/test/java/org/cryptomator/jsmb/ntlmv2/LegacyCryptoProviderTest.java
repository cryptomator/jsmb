package org.cryptomator.jsmb.ntlmv2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HexFormat;

class LegacyCryptoProviderTest {

	// test vectors from https://www.rfc-editor.org/rfc/rfc1320#appendix-A.5
	@DisplayName("test MD4")
	@ParameterizedTest(name = "MD4(\"{0}\") = {1}")
	@CsvSource(textBlock = """
			'', 31d6cfe0d16ae931b73c59d7e0c089c0
			'a', bde52cb31de33e46245e05fbdbd6fb24
			'abc', a448017aaf21d8525fc10ae87aa6729d
			'message digest', d9130a8164549fe818874806e1c7014b
			'abcdefghijklmnopqrstuvwxyz', d79e1c308aa5bbcdeea8ed63df412da9
			'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 043f8582f241db351ce627e153e7f0e4
			'12345678901234567890123456789012345678901234567890123456789012345678901234567890', e33b4ddc9c38f2199c3e7b164fcc0536
			""")
	public void testMd4(String input, String expectedHash) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(LegacyCryptoProvider.MD4, LegacyCryptoProvider.INSTANCE);

		byte[] actualHash = md.digest(input.getBytes(StandardCharsets.US_ASCII));

		Assertions.assertEquals(expectedHash, HexFormat.of().withLowerCase().formatHex(actualHash));
	}

	@Test
	@DisplayName("get LegacyCryptoProvider")
	public void getProvider() {
		Security.addProvider(LegacyCryptoProvider.INSTANCE);

		var provider = Security.getProvider(LegacyCryptoProvider.NAME);

		Assertions.assertNotNull(provider);
		Assertions.assertEquals(LegacyCryptoProvider.NAME, provider.getName());
	}

}