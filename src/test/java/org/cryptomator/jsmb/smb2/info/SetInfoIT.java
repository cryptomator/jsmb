package org.cryptomator.jsmb.smb2.info;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.Server;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SetInfoIT {

	@TempDir
	static Path shareRoot;

	private Server server;
	private SMBClient client;
	private Connection connection;
	private Session session;
	private DiskShare share;

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
		share = (DiskShare) session.connectShare("data");

		Files.writeString(shareRoot.resolve("to-rename.txt"), "content-to-rename");
		Files.writeString(shareRoot.resolve("to-truncate.txt"), "0123456789");
		Files.writeString(shareRoot.resolve("to-delete.txt"), "delete-me");
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
	@DisplayName("File.rename (FileRenameInformation) moves the file on disk")
	public void renameFile() throws IOException {
		try (var file = share.openFile("to-rename.txt",
				EnumSet.of(AccessMask.GENERIC_READ, AccessMask.DELETE),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null)) {

			file.rename("renamed.txt", true);
		}

		Assertions.assertFalse(Files.exists(shareRoot.resolve("to-rename.txt")));
		Assertions.assertTrue(Files.exists(shareRoot.resolve("renamed.txt")));
		Assertions.assertEquals("content-to-rename",
				Files.readString(shareRoot.resolve("renamed.txt"), StandardCharsets.UTF_8));
	}

	@Test
	@Order(2)
	@DisplayName("File.setLength (FileEndOfFileInformation) truncates the file on disk")
	public void truncateFile() throws IOException {
		try (var file = share.openFile("to-truncate.txt",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null)) {

			file.setLength(4);
		}

		Assertions.assertEquals(4, Files.size(shareRoot.resolve("to-truncate.txt")));
		Assertions.assertEquals("0123", Files.readString(shareRoot.resolve("to-truncate.txt"), StandardCharsets.UTF_8));
	}

	@Test
	@Order(3)
	@DisplayName("share.rm deletes the file via FILE_DELETE_ON_CLOSE in CREATE + CLOSE")
	public void deleteViaCreate() {
		share.rm("to-delete.txt");
		Assertions.assertFalse(Files.exists(shareRoot.resolve("to-delete.txt")));
	}

	@Test
	@Order(4)
	@DisplayName("Opening with DELETE + FILE_DELETE_ON_CLOSE deletes the file on close")
	public void deleteOnCloseViaCreateOption() throws IOException {
		Path target = shareRoot.resolve("ephemeral.txt");
		Files.writeString(target, "short-lived");

		try (var file = share.openFile("ephemeral.txt",
				EnumSet.of(AccessMask.DELETE),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				EnumSet.of(SMB2CreateOptions.FILE_DELETE_ON_CLOSE))) {
			// close() triggers the delete
		}

		Assertions.assertFalse(Files.exists(target));
	}
}
