package org.cryptomator.jsmb.smb2.info;

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileAllInformation;
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
import java.nio.file.Files;
import java.nio.file.Path;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class QueryInfoIT {

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

		Files.writeString(shareRoot.resolve("data.bin"), "payload-23bytes-abcdefg");
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
	@DisplayName("share.getFileInformation() returns FileAllInformation with correct size + attributes")
	public void fileAllInformation() {
		FileAllInformation info = share.getFileInformation("data.bin");

		Assertions.assertEquals(23L, info.getStandardInformation().getEndOfFile());
		Assertions.assertFalse(info.getStandardInformation().isDirectory());
		Assertions.assertEquals(0L, info.getStandardInformation().getAllocationSize() % 1);
		Assertions.assertEquals(FileAttributes.FILE_ATTRIBUTE_NORMAL.getValue(),
				info.getBasicInformation().getFileAttributes() & FileAttributes.FILE_ATTRIBUTE_NORMAL.getValue());
		Assertions.assertTrue(info.getNameInformation().startsWith("\\"),
				"FileNameInformation should be backslash-absolute, was: " + info.getNameInformation());
	}

	@Test
	@Order(2)
	@DisplayName("FileAllInformation on a directory carries the FILE_ATTRIBUTE_DIRECTORY bit")
	public void directoryInformation() throws IOException {
		Files.createDirectory(shareRoot.resolve("subdir"));

		FileAllInformation info = share.getFileInformation("subdir");

		Assertions.assertTrue(info.getStandardInformation().isDirectory());
		Assertions.assertNotEquals(0L,
				info.getBasicInformation().getFileAttributes() & FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue());
	}

	@Test
	@Order(3)
	@DisplayName("DiskShare.getShareInformation() exposes non-zero volume size (FileFsFullSizeInformation)")
	public void fsFullSizeInformation() {
		var info = share.getShareInformation();
		Assertions.assertTrue(info.getTotalSpace() > 0, "totalSpace should be positive");
		Assertions.assertTrue(info.getFreeSpace() >= 0);
	}

}
