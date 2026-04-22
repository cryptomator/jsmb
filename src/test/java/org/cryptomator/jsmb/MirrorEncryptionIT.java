package org.cryptomator.jsmb;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2IoctlRequest;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import org.cryptomator.jsmb.Config;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Verifies the spec-mandated "mirror the request's encryption state" clause of MS-SMB2 3.3.4.1.4:
 * even when the server is configured with {@code encryptData=false}, a request that arrived
 * encrypted (because the client forced encryption via {@code SmbConfig.withEncryptData(true)})
 * must be answered with an encrypted response, using the same session keys.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class MirrorEncryptionIT {

	private static final SMB2FileId FILE_ID_NONE = new SMB2FileId(fillByte(8, (byte) 0xFF), fillByte(8, (byte) 0xFF));

	private TcpServer server;
	private SMBClient client;
	private Connection connection;
	private Session session;

	@BeforeAll
	public void setup() throws IOException {
		// Server intentionally has ENCRYPT_DATA disabled — normally responses would be plaintext.
		server = TcpServer.start(0, Config.create(Config.REQUIRE_MESSAGE_SIGNING));
		// Client forces encryption — every post-auth request will be wrapped in a TRANSFORM_HEADER.
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
	@DisplayName("Server mirrors encryption on an encrypted IOCTL even when Config.encryptData=false")
	public void serverMirrorsEncryption() throws Exception {
		// smbj's PacketEncryptor will reject a plaintext response when it expects encryption; the
		// round-trip succeeding at all is the assertion that the server encrypted its response.
		var request = new SMB2IoctlRequest(SMB2Dialect.SMB_3_1_1,
				session.getSessionId(),
				0L,
				0x00140204L, // FSCTL_VALIDATE_NEGOTIATE_INFO
				FILE_ID_NONE,
				new ArrayByteChunkProvider(new byte[0], 0),
				true,
				64);

		var response = session.<SMB2IoctlResponse>send(request).get(5, TimeUnit.SECONDS);

		// STATUS_FILE_CLOSED (0xC0000128) per MS-SMB2 3.3.5.15.12 for dialect 3.1.1.
		Assertions.assertEquals(0xC0000128L, response.getHeader().getStatusCode());
	}

	private static byte[] fillByte(int length, byte value) {
		byte[] result = new byte[length];
		Arrays.fill(result, value);
		return result;
	}
}
