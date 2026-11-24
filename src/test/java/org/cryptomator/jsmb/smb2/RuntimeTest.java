package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.echo.EchoRequest;
import org.cryptomator.jsmb.smb2.echo.EchoResponse;
import org.cryptomator.jsmb.smb2.notify.ChangeNotifyRequest;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class RuntimeTest {

	private Connection connection;
	private Runtime runtime;

	@BeforeEach
	void setUp() {
		var global = new Global(Config.DEFAULT, new Credentials("DOMAIN", "user", "password"));
		connection = new Connection(global);
		runtime = new Runtime(connection);
	}

	@Test
	@DisplayName("LOGOFF removes the session and is acknowledged with STATUS_SUCCESS")
	void logoff() {
		var session = Session.create(connection);
		var header = PacketHeader.builder().command(Command.LOGOFF.value()).sessionId(session.sessionId).build();
		var bodySeg = MemorySegment.ofArray(new byte[4]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 4);
		var request = new LogoffRequest(header, bodySeg);

		var response = runtime.logoff(request);

		Assertions.assertInstanceOf(LogoffResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertFalse(connection.sessionTable.containsKey(session.sessionId));
	}

	@Test
	@DisplayName("ECHO is acknowledged with a 4-byte EchoResponse carrying STATUS_SUCCESS and the request's MessageId")
	void echo() {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.ECHO.value());
		headerSeg.set(Layouts.LE_INT64, 24, 0x42L);  // MessageId at offset 24 per PacketHeader

		var bodySeg = MemorySegment.ofArray(new byte[4]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 4);

		var request = new EchoRequest(new PacketHeader(headerSeg), bodySeg);
		var response = runtime.echo(request);

		Assertions.assertInstanceOf(EchoResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertEquals(Command.ECHO.value(), response.header().command());
		Assertions.assertEquals(0x42L, response.header().messageId());
		Assertions.assertEquals(EchoResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
	}

	@Test
	@DisplayName("CHANGE_NOTIFY is answered with STATUS_NOT_SUPPORTED")
	void changeNotifyNotSupported() {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.CHANGE_NOTIFY.value());

		var bodySeg = MemorySegment.ofArray(new byte[32]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 32);

		var request = new ChangeNotifyRequest(new PacketHeader(headerSeg), bodySeg);
		var response = runtime.changeNotify(request);

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_NOT_SUPPORTED, response.header().status());
	}
}
