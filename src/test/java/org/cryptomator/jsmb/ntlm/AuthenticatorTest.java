package org.cryptomator.jsmb.ntlm;

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
import java.util.Base64;
import java.util.Map;

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
	@DisplayName("test message processing with JDK SaslClient")
	public void testNtlmMessageProcessing() throws SaslException {
		Map<String, ?> props = Map.of(
				Sasl.POLICY_NOPLAINTEXT, "true",
				"com.sun.security.sasl.ntlm.version", "LMv2/NTLMv2",
				"com.sun.security.sasl.ntlm.domain", "localhost"
		);
		CallbackHandler callbackHandler = callbacks -> {
			for (Callback callback : callbacks) {
				switch (callback) {
					case PasswordCallback pc -> pc.setPassword("password".toCharArray());
					case NameCallback nc -> nc.setName("user");
					case RealmCallback rc -> rc.setText("smb");
					default -> throw new UnsupportedCallbackException(callback);
				}
			}
		};
		SaslClient sc = Sasl.createSaslClient(new String[]{"NTLM"}, "user", "smb", "localhost", props, callbackHandler);
		// SaslServer ss = Sasl.createSaslServer("NTLM", null, null, props, callbackHandler);
		Authenticator authenticator = Authenticator.create("user", "password", "localhost");

		byte[] initialResponse = sc.evaluateChallenge(new byte[0]);
		// byte[] serverChallenge = ss.evaluateResponse(initialResponse);
		byte[] serverChallenge = authenticator.process(NtlmMessage.parse(MemorySegment.ofArray(initialResponse))).segment().toArray(Layouts.BYTE);;
		byte[] clientChallenge = sc.evaluateChallenge(serverChallenge);
		authenticator.process(NtlmMessage.parse(MemorySegment.ofArray(clientChallenge)));

		Assertions.assertTrue(sc.isComplete());
	}

}