package org.cryptomator.jsmb.smb2.query;

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import org.cryptomator.jsmb.TcpServer;
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
import java.util.List;
import java.util.stream.Collectors;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class QueryDirectoryIT {

	@TempDir
	static Path shareRoot;

	private TcpServer server;
	private SMBClient client;
	private Connection connection;
	private Session session;
	private DiskShare share;

	@BeforeAll
	public void setup() throws IOException {
		server = TcpServer.start(0);
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

		// Populate a directory to list.
		Files.writeString(shareRoot.resolve("alpha.txt"), "one");
		Files.writeString(shareRoot.resolve("bravo.txt"), "two two");
		Files.createDirectory(shareRoot.resolve("charlie"));
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
	@DisplayName("list() returns every entry with the correct size and directory bit")
	public void listShareRoot() {
		// smbj's list() wraps CREATE on the directory, QUERY_DIRECTORY (paginated), CLOSE.
		List<FileIdBothDirectoryInformation> entries = share.list("");

		var byName = entries.stream().collect(Collectors.toMap(FileIdBothDirectoryInformation::getFileName, e -> e));
		Assertions.assertTrue(byName.containsKey("alpha.txt"));
		Assertions.assertTrue(byName.containsKey("bravo.txt"));
		Assertions.assertTrue(byName.containsKey("charlie"));
		Assertions.assertEquals(3L, byName.get("alpha.txt").getEndOfFile());
		Assertions.assertEquals(7L, byName.get("bravo.txt").getEndOfFile());
		Assertions.assertNotEquals(0L, byName.get("charlie").getFileAttributes() & FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue());
	}

	@Test
	@Order(2)
	@DisplayName("list() with a glob pattern filters the returned entries")
	public void listWithPattern() {
		List<FileIdBothDirectoryInformation> entries = share.list("", "*.txt");

		var names = entries.stream().map(FileIdBothDirectoryInformation::getFileName).sorted().toList();
		Assertions.assertEquals(List.of("alpha.txt", "bravo.txt"), names);
	}

	@Test
	@Order(3)
	@DisplayName("list() on a pattern that matches nothing returns an empty list (smbj masks STATUS_NO_SUCH_FILE)")
	public void listWithNoMatches() {
		// smbj swallows STATUS_NO_SUCH_FILE from the server and surfaces it as an empty list.
		List<FileIdBothDirectoryInformation> entries = share.list("", "*.nope");
		Assertions.assertTrue(entries.isEmpty());
	}

	@Test
	@Order(4)
	@DisplayName("list() on an empty directory returns an empty list (smbj masks STATUS_NO_SUCH_FILE)")
	public void listEmptyDirectory() throws IOException {
		Files.createDirectory(shareRoot.resolve("empty-dir"));
		List<FileIdBothDirectoryInformation> entries = share.list("empty-dir");
		Assertions.assertTrue(entries.isEmpty());
	}

	@Test
	@Order(5)
	@DisplayName("Nested directory created via smbj mkdir is visible in a subsequent list()")
	public void nestedDirectory() {
		share.mkdir("charlie\\deep");
		List<FileIdBothDirectoryInformation> entries = share.list("charlie");
		var names = entries.stream().map(FileIdBothDirectoryInformation::getFileName).toList();
		Assertions.assertTrue(names.contains("deep"), "expected 'deep' in " + names);
	}
}
