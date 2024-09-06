package org.cryptomator.jsmb.ntlm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.util.Base64;

class AuthenticatorTest {

	// test case from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26
	@Test
	@DisplayName("LMOWFv2")
	public void testLmowf() throws InvalidKeyException {
		byte[] expectedResult = Base64.getDecoder().decode("DIaKQDv9epOjAB7yLvAuPw==");

		byte[] result = Authenticator.LMOWFv2("Password", "User", "Domain");

		Assertions.assertArrayEquals(expectedResult, result);
	}

}