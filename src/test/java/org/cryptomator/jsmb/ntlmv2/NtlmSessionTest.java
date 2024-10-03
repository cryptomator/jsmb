package org.cryptomator.jsmb.ntlmv2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.util.Map;

class NtlmSessionTest {

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
					case RealmCallback rc -> rc.setText("localhost");
					default -> throw new UnsupportedCallbackException(callback);
				}
			}
		};
		SaslClient sc = Sasl.createSaslClient(new String[]{"NTLM"}, "user", "jsmb", "localhost", props, callbackHandler);
		// SaslServer ss = Sasl.createSaslServer("NTLM", null, null, props, callbackHandler);

		byte[] negotiateMessage = sc.evaluateChallenge(new byte[0]);
		// byte[] serverChallenge = ss.evaluateResponse(initialResponse);
		var ntlmSession = NtlmSession.create().negotiate(negotiateMessage);
		byte[] clientChallenge = sc.evaluateChallenge(ntlmSession.serverChallenge());

		Assertions.assertDoesNotThrow(() -> ntlmSession.authenticate(clientChallenge, "user", "password", "localhost"));

		Assertions.assertTrue(sc.isComplete());
	}

}