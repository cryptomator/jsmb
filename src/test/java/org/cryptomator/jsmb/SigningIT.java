package org.cryptomator.jsmb;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import org.cryptomator.jsmb.share.nio.NioShare;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Drives a session that is signed but not encrypted, so that every request passes through the server's signature verification
 * (MS-SMB2 3.3.5.2.4). All other integration tests run encrypted, where the AEAD cipher takes the place of signatures.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SigningIT {

	@TempDir
	static Path shareRoot;

	private Server server;
	private SMBClient client;
	private Connection connection;
	private Session session;
	private DiskShare share;

	@BeforeAll
	public void setup() throws IOException {
		// no ENCRYPT_DATA: the session stays unencrypted and therefore requires signing
		server = Server.start(0, Config.create(Config.REQUIRE_MESSAGE_SIGNING), new Credentials("DOMAIN", "user", "password"));
		server.registerShare("data", new NioShare(shareRoot));
		var config = SmbConfig.builder()
				.withMultiProtocolNegotiate(true)
				.withEncryptData(false)
				.withSigningRequired(true)
				.build();
		client = new SMBClient(config);
		connection = client.connect("localhost", server.getLocalPort());
		session = connection.authenticate(new AuthenticationContext("user", "password".toCharArray(), "DOMAIN"));
		share = (DiskShare) session.connectShare("data");
	}

	@AfterAll
	public void tearDown() throws IOException {
		if (share != null && share.isConnected()) share.close();
		if (connection != null) connection.close();
		if (client != null) client.close();
		if (server != null) server.close();
	}

	@Test
	@Order(1)
	@DisplayName("The session is signed and not encrypted")
	public void sessionIsSignedNotEncrypted() throws IOException {
		Assertions.assertTrue(session.isSigningRequired());
		Assertions.assertFalse(session.shouldEncryptData());
	}

	@Test
	@Order(2)
	@DisplayName("Signed CREATE and CLOSE requests are accepted")
	public void mkdir() {
		share.mkdir("signed");

		Assertions.assertTrue(Files.isDirectory(shareRoot.resolve("signed")));
	}

	@Test
	@Order(3)
	@DisplayName("Signed QUERY_DIRECTORY requests are accepted")
	public void list() {
		var entries = share.list("");

		Assertions.assertTrue(entries.stream().anyMatch(e -> e.getFileName().equals("signed")), "Expected 'signed' in listing, got: " + entries);
	}
}
