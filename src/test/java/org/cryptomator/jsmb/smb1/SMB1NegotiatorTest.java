package org.cryptomator.jsmb.smb1;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.Server;
import org.cryptomator.jsmb.common.DisconnectException;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.Dialects;
import org.cryptomator.jsmb.smb2.NegotiateResponse;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

class SMB1NegotiatorTest {

	private Server server;
	private Connection connection;
	private SMB1Negotiator negotiator;

	@BeforeEach
	void setUp() throws IOException {
		server = Server.start(0, Config.create(), new Credentials("DOMAIN", "user", "password"));
		connection = new Connection(server.global);
		negotiator = new SMB1Negotiator(server, connection);
	}

	@AfterEach
	void tearDown() throws IOException {
		if (server != null) server.close();
	}

	@Test
	@DisplayName("A multi-protocol negotiate offering \"SMB 2.???\" is answered with the SMB2 wildcard dialect, which becomes the connection's NegotiateDialect")
	void multiProtocolNegotiate() {
		var request = negotiateRequest("NT LM 0.12", "SMB 2.002", "SMB 2.???");

		var response = negotiator.negotiate(request);

		Assertions.assertInstanceOf(NegotiateResponse.class, response);
		Assertions.assertEquals(Dialects.SMB2_WILDCARD, connection.negotiateDialect);
	}

	@ParameterizedTest(name = "NegotiateDialect 0x{0}")
	@DisplayName("SMB_COM_NEGOTIATE on a connection that has already been negotiated drops the connection")
	@ValueSource(strings = {"02ff", "0311"})
	void repeatedNegotiate(String negotiateDialect) {
		connection.negotiateDialect = (char) Integer.parseInt(negotiateDialect, 16);
		var request = negotiateRequest("SMB 2.???");

		Assertions.assertThrows(DisconnectException.class, () -> negotiator.negotiate(request));
	}

	// SMB_COM_NEGOTIATE with no parameter words and one 0x02-prefixed, null-terminated string per dialect
	private static SmbComNegotiateRequest negotiateRequest(String... dialects) {
		var data = new ByteArrayOutputStream();
		for (var dialect : dialects) {
			data.write(0x02);
			data.writeBytes(dialect.getBytes(StandardCharsets.US_ASCII));
			data.write(0x00);
		}
		var segment = MemorySegment.ofArray(new byte[32 + 1 + 2 + data.size()]); // header + word count + byte count + bytes
		segment.set(Layouts.LE_INT32, 0, SMB1Message.PROTOCOL_ID);
		segment.set(Layouts.BYTE, 4, (byte) SmbComNegotiateRequest.COMMAND);
		segment.set(Layouts.LE_UINT16, 33, (char) data.size());
		MemorySegment.copy(MemorySegment.ofArray(data.toByteArray()), 0, segment, 35, data.size());
		return new SmbComNegotiateRequest(segment);
	}
}
