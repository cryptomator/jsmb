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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class WriteIT {

	@TempDir
	static Path shareRoot;

	private TcpServer server;
	private SMBClient client;
	private Connection connection;
	private Session session;
	private DiskShare share;

	@BeforeAll
	public void setup() throws IOException {
		server = TcpServer.start(0, new Credentials("DOMAIN", "user", "password"));
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
	@DisplayName("openFile().getOutputStream() writes the full content of a small file to disk")
	public void writeSmallFile() throws IOException {
		byte[] payload = "hello-write".getBytes(StandardCharsets.UTF_8);
		try (var file = share.openFile("small.txt",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_CREATE,
				null);
			 OutputStream out = file.getOutputStream()) {

			out.write(payload);
		}
		Assertions.assertArrayEquals(payload, Files.readAllBytes(shareRoot.resolve("small.txt")));
	}

	@Test
	@Order(2)
	@DisplayName("FLUSH after a write round-trips without error")
	public void flushAfterWrite() throws IOException {
		try (var file = share.openFile("flushed.txt",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_CREATE,
				null)) {

			file.write("abc".getBytes(StandardCharsets.UTF_8), 0);
			file.flush();
		}
		Assertions.assertArrayEquals("abc".getBytes(StandardCharsets.UTF_8),
				Files.readAllBytes(shareRoot.resolve("flushed.txt")));
	}

	@Test
	@Order(3)
	@DisplayName("Writing 256 KiB round-trips byte-for-byte through smbj's chunking writer")
	public void writeLargeFile() throws IOException {
		byte[] payload = new byte[256 * 1024];
		for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i % 251);

		try (var file = share.openFile("big.bin",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_CREATE,
				null);
			 OutputStream out = file.getOutputStream()) {

			out.write(payload);
		}
		byte[] onDisk = Files.readAllBytes(shareRoot.resolve("big.bin"));
		Assertions.assertEquals(payload.length, onDisk.length);
		for (int i = 0; i < payload.length; i++) {
			Assertions.assertEquals(payload[i], onDisk[i], "mismatch at index " + i);
		}
	}

	@Test
	@Order(4)
	@DisplayName("Writing at a non-zero offset leaves the preceding bytes intact")
	public void writeAtOffset() throws IOException {
		try (var file = share.openFile("offset.bin",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				null,
				SMB2ShareAccess.ALL,
				SMB2CreateDisposition.FILE_CREATE,
				null)) {

			file.write("head".getBytes(StandardCharsets.UTF_8), 0);
			file.write("tail".getBytes(StandardCharsets.UTF_8), 4);
		}
		Assertions.assertEquals("headtail", Files.readString(shareRoot.resolve("offset.bin"), StandardCharsets.UTF_8));
	}
}
