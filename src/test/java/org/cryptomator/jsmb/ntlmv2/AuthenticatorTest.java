package org.cryptomator.jsmb.ntlmv2;

import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.*;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

// to be run with `--add-reads org.cryptomator.jsmb=java.security.sasl`
class AuthenticatorTest {

	// test case from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26
	@Test
	@DisplayName("LMOWFv2")
	public void testLmowf() {
		byte[] expectedResult = Base64.getDecoder().decode("DIaKQDv9epOjAB7yLvAuPw==");

		byte[] result = Authenticator.LMOWFv2("Password", "User", "Domain");

		Assertions.assertArrayEquals(expectedResult, result);
	}

	@Test
	@DisplayName("test authentication")
	public void testNtlmV2Auth() {
		// test case from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bc612491-fb0b-4829-91bc-7c6b95ff67fe
		var challenge = new NtlmChallengeMessage(MemorySegment.ofArray(Base64.getDecoder().decode("TlRMTVNTUAACAAAADAAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABEAAAABgBwFwAAAA9TAGUAcgB2AGUAcgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA=")));
		var auth = new NtlmAuthenticateMessage(MemorySegment.ofArray(Base64.getDecoder().decode("TlRMTVNTUAADAAAAGAAYAGwAAABUAFQAhAAAAAwADABIAAAACAAIAFQAAAAQABAAXAAAABAAEADYAAAANYKI4gUBKAoAAAAPRABvAG0AYQBpAG4AVQBzAGUAcgBDAE8ATQBQAFUAVABFAFIAhsNQl6yc7BAlVHZKV8zMGaqqqqqqqqqqaM0KuFHlHJaqvJJ76+9qHAEBAAAAAAAAAAAAAAAAAACqqqqqqqqqqgAAAAACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAAAAAAAxdrSVE/JeZCUzhzpC8nQPg==")));

		var response = Assertions.assertDoesNotThrow(() -> Authenticator.ntlmV2Auth(challenge, auth, "User", "Password", "Domain"));

		// see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/daefb605-78d5-4657-a3a0-b9ad11281d07
		Assertions.assertArrayEquals(Base64.getDecoder().decode("hsNQl6yc7BAlVHZKV8zMGaqqqqqqqqqq"), response.lmChallengeResponse());
		Assertions.assertArrayEquals(Base64.getDecoder().decode("aM0KuFHlHJaqvJJ76+9qHA=="), Arrays.copyOf(response.ntChallengeResponse(), 16));
		Assertions.assertArrayEquals(Base64.getDecoder().decode("jeQMytvBSoLxXLCtDelcow=="), response.sessionBaseKey());
	}

}