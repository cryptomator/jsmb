package org.cryptomator.jsmb.smb2.ioctl;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2IoctlRequest;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class IoctlIT {

	private static final int FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204;
	private static final int FSCTL_UNRECOGNIZED = 0x00DEAD00;
	private static final SMB2FileId FILE_ID_NONE = new SMB2FileId(fillByte(8, (byte) 0xFF), fillByte(8, (byte) 0xFF));

	private Server server;
	private SMBClient client;
	private Connection connection;
	private Session session;

	@BeforeAll
	public void setup() throws IOException {
		server = Server.start(0, new Credentials("DOMAIN", "user", "password"));
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
		if (connection != null) connection.close();
		if (client != null) client.close();
		if (server != null) server.close();
	}

	@Test
	@Order(1)
	@DisplayName("FSCTL_VALIDATE_NEGOTIATE_INFO is rejected with STATUS_FILE_CLOSED")
	public void validateNegotiateInfoIsRejectedWithFileClosed() throws Exception {
		var request = new SMB2IoctlRequest(SMB2Dialect.SMB_3_1_1,
				session.getSessionId(),
				0L, // no tree connect for VALIDATE_NEGOTIATE_INFO
				FSCTL_VALIDATE_NEGOTIATE_INFO,
				FILE_ID_NONE,
				new ArrayByteChunkProvider(new byte[0], 0), // no input — server rejects before parsing per MS-SMB2 3.3.5.15.12
				true, // fsctl
				64);

		var response = session.<SMB2IoctlResponse>send(request).get(5, TimeUnit.SECONDS);

		Assertions.assertEquals(NtStatus.STATUS_FILE_CLOSED.getValue(), response.getHeader().getStatusCode());
	}

	@Test
	@Order(2)
	@DisplayName("Unknown FSCTL is rejected with STATUS_INVALID_DEVICE_REQUEST")
	public void unknownFsctlIsRejectedWithInvalidDeviceRequest() throws Exception {
		var request = new SMB2IoctlRequest(SMB2Dialect.SMB_3_1_1,
				session.getSessionId(),
				0L,
				FSCTL_UNRECOGNIZED,
				FILE_ID_NONE,
				new ArrayByteChunkProvider(new byte[0], 0),
				true,
				64);

		var response = session.<SMB2IoctlResponse>send(request).get(5, TimeUnit.SECONDS);

		// smbj's NtStatus enum doesn't expose STATUS_INVALID_DEVICE_REQUEST as a constant; the raw NT value is 0xC0000010
		Assertions.assertEquals(0xC0000010L, response.getHeader().getStatusCode());
	}

	private static byte[] fillByte(int length, byte value) {
		byte[] result = new byte[length];
		Arrays.fill(result, value);
		return result;
	}
}
