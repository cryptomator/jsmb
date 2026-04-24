package org.cryptomator.jsmb.smb2.create;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Set;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CreateIT {

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
	@DisplayName("Opening the share root (empty path) succeeds")
	public void openShareRoot() {
		try (var dir = share.openDirectory("",
				EnumSet.of(AccessMask.GENERIC_READ),
				EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
				allShareAccess(),
				SMB2CreateDisposition.FILE_OPEN,
				EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE))) {
			Assertions.assertNotNull(dir.getFileId());
		}
	}

	@Test
	@Order(2)
	@DisplayName("Opening a missing file returns STATUS_OBJECT_NAME_NOT_FOUND")
	public void openMissingFile() {
		var e = Assertions.assertThrows(SMBApiException.class, () ->
				share.openFile("ghost.txt",
						EnumSet.of(AccessMask.GENERIC_READ),
						EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
						allShareAccess(),
						SMB2CreateDisposition.FILE_OPEN,
						EnumSet.noneOf(SMB2CreateOptions.class)));
		Assertions.assertEquals(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, e.getStatus());
	}

	@Test
	@Order(3)
	@DisplayName("Creating a new file materializes it on disk")
	public void createNewFile() {
		try (var file = share.openFile("hello.txt",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
				allShareAccess(),
				SMB2CreateDisposition.FILE_CREATE,
				EnumSet.noneOf(SMB2CreateOptions.class))) {
			Assertions.assertNotNull(file.getFileId());
		}
		Assertions.assertTrue(Files.isRegularFile(shareRoot.resolve("hello.txt")));
	}

	@Test
	@Order(4)
	@DisplayName("Creating a file that already exists returns STATUS_OBJECT_NAME_COLLISION")
	public void createExistingFileFails() {
		var e = Assertions.assertThrows(SMBApiException.class, () ->
				share.openFile("hello.txt",
						EnumSet.of(AccessMask.GENERIC_WRITE),
						EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
						allShareAccess(),
						SMB2CreateDisposition.FILE_CREATE,
						EnumSet.noneOf(SMB2CreateOptions.class)));
		Assertions.assertEquals(NtStatus.STATUS_OBJECT_NAME_COLLISION, e.getStatus());
	}

	@Test
	@Order(5)
	@DisplayName("Creating a new directory (FILE_DIRECTORY_FILE + FILE_CREATE) materializes it on disk")
	public void mkdirViaCreate() {
		try (var dir = share.openDirectory("subdir",
				EnumSet.of(AccessMask.GENERIC_WRITE),
				EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
				allShareAccess(),
				SMB2CreateDisposition.FILE_CREATE,
				EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE))) {
			Assertions.assertNotNull(dir.getFileId());
		}
		Assertions.assertTrue(Files.isDirectory(shareRoot.resolve("subdir")));
	}

	@Test
	@Order(6)
	@DisplayName("FILE_DELETE_ON_CLOSE removes the file when the handle closes")
	public void deleteOnClose() {
		try (var _ = share.openFile("doomed.txt",
				EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.DELETE),
				EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
				allShareAccess(),
				SMB2CreateDisposition.FILE_CREATE,
				EnumSet.of(SMB2CreateOptions.FILE_DELETE_ON_CLOSE))) {
			Assertions.assertTrue(Files.exists(shareRoot.resolve("doomed.txt")));
		}
		Assertions.assertFalse(Files.exists(shareRoot.resolve("doomed.txt")));
	}

	private static Set<SMB2ShareAccess> allShareAccess() {
		return EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess.FILE_SHARE_DELETE);
	}
}
