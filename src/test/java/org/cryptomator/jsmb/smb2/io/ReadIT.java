package org.cryptomator.jsmb.smb2.io;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ReadIT {

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

		Files.writeString(shareRoot.resolve("small.txt"), "hello-world-12345");
		// Deliberately larger than one SMB2 READ to exercise multi-chunk reads inside smbj.
		byte[] big = new byte[256 * 1024];
		for (int i = 0; i < big.length; i++) big[i] = (byte) (i % 251);
		Files.write(shareRoot.resolve("big.bin"), big);
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
	@DisplayName("openFile().getInputStream() reads the full content of a 17-byte file")
	public void readSmallFile() throws IOException {
		try (var file = share.openFile("small.txt",
				EnumSet.of(AccessMask.GENERIC_READ),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null);
			 InputStream in = file.getInputStream()) {

			byte[] data = in.readAllBytes();
			Assertions.assertEquals("hello-world-12345", new String(data, StandardCharsets.UTF_8));
		}
	}

	@Test
	@Order(2)
	@DisplayName("read(offset, length) at a mid-file offset returns the requested slice")
	public void readAtOffset() throws IOException {
		try (var file = share.openFile("small.txt",
				EnumSet.of(AccessMask.GENERIC_READ),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null)) {

			byte[] buf = new byte[5];
			int n = file.read(buf, 12, 0, buf.length);
			Assertions.assertEquals(5, n);
			Assertions.assertEquals("12345", new String(buf, StandardCharsets.UTF_8));
		}
	}

	@Test
	@Order(3)
	@DisplayName("Reading a 256 KiB file round-trips byte-for-byte through smbj's chunking reader")
	public void readLargeFile() throws IOException {
		try (var file = share.openFile("big.bin",
				EnumSet.of(AccessMask.GENERIC_READ),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null);
			 InputStream in = file.getInputStream()) {

			byte[] data = in.readAllBytes();
			Assertions.assertEquals(256 * 1024, data.length);
			for (int i = 0; i < data.length; i++) {
				Assertions.assertEquals((byte) (i % 251), data[i], "mismatch at index " + i);
			}
		}
	}

	@Test
	@Order(4)
	@DisplayName("Reading past end-of-file returns -1 — smbj maps the server's STATUS_END_OF_FILE to the InputStream EOF convention")
	public void readPastEof() throws IOException {
		try (var file = share.openFile("small.txt",
				EnumSet.of(AccessMask.GENERIC_READ),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_OPEN,
				null)) {

			byte[] buf = new byte[10];
			int n = file.read(buf, 100, 0, buf.length);
			Assertions.assertEquals(-1, n);
		}
	}
}
