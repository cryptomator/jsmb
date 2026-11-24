package org.cryptomator.jsmb;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
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
import java.util.EnumSet;

/**
 * Verifies that the server releases what a client leaves behind. The tests open a file with FILE_DELETE_ON_CLOSE and never close it,
 * so the file disappearing proves that the server closed the handle on its own.
 * Every test uses a connection of its own, since tearing it down is what gets tested.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class TeardownIT {

	@TempDir
	static Path shareRoot;

	private Server server;
	private SMBClient client;

	@BeforeAll
	public void setup() throws IOException {
		server = Server.start(0, new Credentials("DOMAIN", "user", "password"));
		server.registerShare("data", new NioShare(shareRoot));
		client = new SMBClient(SmbConfig.builder().withMultiProtocolNegotiate(true).withEncryptData(true).build());
	}

	@AfterAll
	public void tearDown() throws IOException {
		if (client != null) client.close();
		if (server != null) server.close();
	}

	@Test
	@Order(1)
	@DisplayName("TREE_DISCONNECT closes the handles that are still open on the tree")
	public void treeDisconnect() throws IOException {
		try (var connection = client.connect("localhost", server.getLocalPort())) {
			var session = connection.authenticate(new AuthenticationContext("user", "password".toCharArray(), "DOMAIN"));
			var share = (DiskShare) session.connectShare("data");
			openForDeletion(share, "tree-disconnect.txt");

			share.close();

			Assertions.assertFalse(Files.exists(shareRoot.resolve("tree-disconnect.txt")));
		}
	}

	@Test
	@Order(2)
	@DisplayName("LOGOFF is acknowledged")
	public void logoff() throws IOException {
		try (var connection = client.connect("localhost", server.getLocalPort())) {
			var session = connection.authenticate(new AuthenticationContext("user", "password".toCharArray(), "DOMAIN"));

			Assertions.assertDoesNotThrow(session::logoff);
		}
	}

	@Test
	@Order(3)
	@DisplayName("Losing the connection closes the handles that are still open")
	public void connectionLoss() throws IOException, InterruptedException {
		var connection = client.connect("localhost", server.getLocalPort());
		var session = connection.authenticate(new AuthenticationContext("user", "password".toCharArray(), "DOMAIN"));
		var share = (DiskShare) session.connectShare("data");
		openForDeletion(share, "connection-loss.txt");

		connection.close(true); // drops the transport without TREE_DISCONNECT or LOGOFF

		// the server notices asynchronously
		var file = shareRoot.resolve("connection-loss.txt");
		for (int i = 0; i < 50 && Files.exists(file); i++) {
			Thread.sleep(100);
		}
		Assertions.assertFalse(Files.exists(file));
	}

	// creates a file and leaves its handle open
	private void openForDeletion(DiskShare share, String name) {
		share.openFile(name, EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.DELETE), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, EnumSet.of(SMB2CreateOptions.FILE_DELETE_ON_CLOSE));
		Assertions.assertTrue(Files.exists(shareRoot.resolve(name)));
	}
}
