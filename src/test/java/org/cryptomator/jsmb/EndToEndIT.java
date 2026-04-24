package org.cryptomator.jsmb;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.fileinformation.FileAllInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;

/**
 * End-to-end test against a freshly-mounted share. Each {@code @Order} step exercises one SMB2 command and
 * depends on the preceding ones — together they match the "user plugs a share into Finder, mkdirs, writes a file,
 * stats it, reads it, renames it, deletes it, unmounts" flow.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class EndToEndIT {

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
	@DisplayName("mkdir \"subdir\" lands a new directory in the share root")
	public void mkdirSubdir() {
		share.mkdir("subdir");
		Assertions.assertTrue(Files.isDirectory(shareRoot.resolve("subdir")));
	}

	@Test
	@Order(2)
	@DisplayName("create + write \"subdir/a.txt\" persists the payload on disk")
	public void createAndWriteFile() throws IOException {
		byte[] payload = "end-to-end payload".getBytes(StandardCharsets.UTF_8);
		try (var file = share.openFile("subdir\\a.txt",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				null,
				com.hierynomus.mssmb2.SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_CREATE,
				null);
			 OutputStream out = file.getOutputStream()) {
			out.write(payload);
		}
		Assertions.assertArrayEquals(payload, Files.readAllBytes(shareRoot.resolve("subdir").resolve("a.txt")));
	}

	@Test
	@Order(3)
	@DisplayName("list \"subdir\" returns the newly-created file")
	public void listSubdir() {
		var entries = share.list("subdir");
		Assertions.assertTrue(entries.stream().anyMatch(e -> e.getFileName().equals("a.txt")),
				"Expected 'a.txt' in listing, got: " + entries);
	}

	@Test
	@Order(4)
	@DisplayName("getFileInformation(\"subdir/a.txt\") returns size and attributes matching disk state")
	public void statFile() {
		FileAllInformation info = share.getFileInformation("subdir\\a.txt");

		Assertions.assertEquals(18L, info.getStandardInformation().getEndOfFile());
		Assertions.assertFalse(info.getStandardInformation().isDirectory());
	}

	@Test
	@Order(5)
	@DisplayName("read \"subdir/a.txt\" returns the bytes we just wrote")
	public void readFile() throws IOException {
		try (var file = share.openFile("subdir\\a.txt",
				EnumSet.of(AccessMask.GENERIC_READ),
				null,
				com.hierynomus.mssmb2.SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null);
			 InputStream in = file.getInputStream()) {

			byte[] data = in.readAllBytes();
			Assertions.assertEquals("end-to-end payload", new String(data, StandardCharsets.UTF_8));
		}
	}

	@Test
	@Order(6)
	@DisplayName("rename \"subdir/a.txt\" → \"subdir/b.txt\" moves the file on disk")
	public void renameFile() throws IOException {
		try (var file = share.openFile("subdir\\a.txt",
				EnumSet.of(AccessMask.GENERIC_READ, AccessMask.DELETE),
				null,
				com.hierynomus.mssmb2.SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null)) {

			file.rename("subdir\\b.txt", false);
		}
		Assertions.assertFalse(Files.exists(shareRoot.resolve("subdir").resolve("a.txt")));
		Assertions.assertTrue(Files.exists(shareRoot.resolve("subdir").resolve("b.txt")));
	}

	@Test
	@Order(7)
	@DisplayName("delete-on-close of \"subdir/b.txt\" unlinks the file")
	public void deleteFile() throws IOException {
		//noinspection EmptyTryBlock
		try (var _ = share.openFile("subdir\\b.txt",
				EnumSet.of(AccessMask.DELETE),
				null,
				com.hierynomus.mssmb2.SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				EnumSet.of(SMB2CreateOptions.FILE_DELETE_ON_CLOSE))) {
			// close() triggers the unlink
		}
		Assertions.assertFalse(Files.exists(shareRoot.resolve("subdir").resolve("b.txt")));
	}

}
