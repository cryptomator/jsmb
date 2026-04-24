package org.cryptomator.jsmb;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class ConnectIT {

	private Server server;
	private SMBClient client;

	@BeforeEach
	public void setup() throws IOException {
		server = Server.start(0, new Credentials("DOMAIN", "user", "password"));
		SmbConfig config = SmbConfig.builder()
				.withMultiProtocolNegotiate(true) //
				.withEncryptData(true) //
				.withSigningEnabled(true) //
				.build();
		client = new SMBClient(config);
	}

	@AfterEach
	public void tearDown() throws IOException {
		if (client != null) {
			client.close();
		}
		if (server != null) {
			server.close();
		}
	}

	@Test
	@DisplayName("Attempt to connect with invalid credentials")
	public void connectWithInvalidCredentials() throws IOException {
		try (Connection connection = client.connect("localhost", server.getLocalPort())) {
			AuthenticationContext ac = new AuthenticationContext("user", "wrongPassword".toCharArray(), "DOMAIN");
			var e = Assertions.assertThrows(SMBApiException.class, () -> connection.authenticate(ac));
			Assertions.assertEquals(NtStatus.STATUS_LOGON_FAILURE, e.getStatus());
		}
	}

	@Test
	@DisplayName("Connect and disconnect with valid credentials")
	public void connectAndDisconnect() throws IOException {
		try (Connection connection = client.connect("localhost", server.getLocalPort())) {
			AuthenticationContext ac = new AuthenticationContext("user", "password".toCharArray(), "DOMAIN");
			Session session = connection.authenticate(ac);
			// with encryption negotiated (Global.encryptData=true), the server sets SMB2_SESSION_FLAG_ENCRYPT_DATA
			// on the final SESSION_SETUP response, which causes smbj to disable signing in favor of AEAD integrity
			Assertions.assertTrue(session.shouldEncryptData());
			Assertions.assertFalse(session.isSigningRequired());
		}
	}
}
