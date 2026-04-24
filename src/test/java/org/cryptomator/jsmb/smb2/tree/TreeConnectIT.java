package org.cryptomator.jsmb.smb2.tree;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import org.cryptomator.jsmb.Server;
import org.cryptomator.jsmb.Credentials;
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
import java.nio.file.Path;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class TreeConnectIT {

	@TempDir
	static Path shareRoot;

	private Server server;
	private SMBClient client;
	private Connection connection;
	private Session session;
	private DiskShare connectedShare;

	@BeforeAll
	public void setup() throws IOException {
		server = Server.start(0, new Credentials("DOMAIN", "user", "password"));
		server.registerShare("data", new NioShare(shareRoot));
		var config = SmbConfig.builder()
				.withMultiProtocolNegotiate(true)
				.withEncryptData(true)
				.withSigningEnabled(true)
				.build();
		client = new SMBClient(config);
		connection = client.connect("localhost", server.getLocalPort());
		session = connection.authenticate(new AuthenticationContext("user", "password".toCharArray(), "DOMAIN"));
	}

	@AfterAll
	public void tearDown() throws IOException {
		if (connectedShare != null && connectedShare.isConnected()) connectedShare.close();
		if (connection != null) connection.close();
		if (client != null) client.close();
		if (server != null) server.close();
	}

	@Test
	@Order(1)
	@DisplayName("TREE_CONNECT to a registered share succeeds and returns a DiskShare")
	public void treeConnect() {
		connectedShare = (DiskShare) session.connectShare("data");
		Assertions.assertTrue(connectedShare.isConnected());
		Assertions.assertEquals("data", connectedShare.getSmbPath().getShareName());
	}

	@Test
	@Order(2)
	@DisplayName("TREE_DISCONNECT releases the share")
	public void treeDisconnect() throws IOException {
		Assertions.assertNotNull(connectedShare, "preceding tree-connect must have populated the share");
		connectedShare.close();
		Assertions.assertFalse(connectedShare.isConnected());
	}

	@Test
	@Order(3)
	@DisplayName("TREE_CONNECT to an unknown share returns STATUS_BAD_NETWORK_NAME")
	public void treeConnectUnknownShare() {
		var e = Assertions.assertThrows(SMBApiException.class, () -> session.connectShare("does-not-exist"));
		Assertions.assertEquals(NtStatus.STATUS_BAD_NETWORK_NAME, e.getStatus());
	}
}
