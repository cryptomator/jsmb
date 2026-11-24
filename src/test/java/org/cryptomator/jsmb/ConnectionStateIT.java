package org.cryptomator.jsmb;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.DataInputStream;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.Socket;

/**
 * Sends hand-built packets over a raw socket, as no SMB client would violate the protocol the way these tests need to.
 * Every test uses a connection of its own, since the server is expected to drop it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ConnectionStateIT {

	private Server server;

	@BeforeAll
	public void setup() throws IOException {
		server = Server.start(0, new Credentials("DOMAIN", "user", "password"));
	}

	@AfterAll
	public void tearDown() throws IOException {
		if (server != null) server.close();
	}

	@Test
	@Order(1)
	@DisplayName("A request other than NEGOTIATE on a fresh connection drops the connection without a reply")
	public void requestBeforeNegotiate() throws IOException {
		try (var socket = new Socket("localhost", server.getLocalPort())) {
			socket.setSoTimeout(5000);
			send(socket, smb2Message(Command.ECHO.value())); // ECHO needs neither session nor tree connect, so nothing else would reject it

			int firstByte = socket.getInputStream().read();

			Assertions.assertEquals(-1, firstByte, "expected end of stream instead of a response");
		}
	}

	@Test
	@Order(2)
	@DisplayName("A command code that the protocol doesn't define drops the connection without a reply")
	public void unknownCommand() throws IOException {
		try (var socket = new Socket("localhost", server.getLocalPort())) {
			socket.setSoTimeout(5000);
			send(socket, smb2Message((char) 0x0013));

			int firstByte = socket.getInputStream().read();

			Assertions.assertEquals(-1, firstByte, "expected end of stream instead of a response");
		}
	}

	@Test
	@Order(3)
	@DisplayName("A MessageId outside of the command sequence window drops the connection without a reply")
	public void messageIdOutsideWindow() throws IOException {
		try (var socket = new Socket("localhost", server.getLocalPort())) {
			socket.setSoTimeout(5000);
			send(socket, negotiateWithoutDialects(1L)); // a fresh connection only accepts MessageId 0

			int firstByte = socket.getInputStream().read();

			Assertions.assertEquals(-1, firstByte, "expected end of stream instead of a response");
		}
	}

	@Test
	@Order(4)
	@DisplayName("An error response grants a credit, and reusing a MessageId drops the connection without a reply")
	public void reusedMessageId() throws IOException {
		try (var socket = new Socket("localhost", server.getLocalPort())) {
			socket.setSoTimeout(5000);
			var in = new DataInputStream(socket.getInputStream());
			send(socket, negotiateWithoutDialects(0L));
			var errorResponse = new PacketHeader(MemorySegment.ofArray(in.readNBytes(in.readInt())).asSlice(0, PacketHeader.STRUCTURE_SIZE));
			Assertions.assertEquals(NTStatus.STATUS_INVALID_PARAMETER, errorResponse.status());
			Assertions.assertEquals(1, errorResponse.creditResponse());
			send(socket, negotiateWithoutDialects(0L));

			int firstByte = in.read();

			Assertions.assertEquals(-1, firstByte, "expected end of stream instead of a response");
		}
	}

	@Test
	@Order(5)
	@DisplayName("A NEGOTIATE whose negotiate contexts lie outside of the message is failed with STATUS_INVALID_PARAMETER")
	public void negotiateContextsOutsideMessage() throws IOException {
		try (var socket = new Socket("localhost", server.getLocalPort())) {
			socket.setSoTimeout(5000);
			var in = new DataInputStream(socket.getInputStream());
			var header = PacketHeader.builder().command(Command.NEGOTIATE.value()).messageId(0L).build();
			var message = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE + 40]);
			MemorySegment.copy(header.segment(), 0, message, 0, PacketHeader.STRUCTURE_SIZE);
			var body = message.asSlice(PacketHeader.STRUCTURE_SIZE);
			body.set(Layouts.LE_UINT16, 0, (char) 36); // StructureSize
			body.set(Layouts.LE_UINT16, 2, (char) 1); // DialectCount
			body.set(Layouts.LE_INT32, 28, 0x1000); // NegotiateContextOffset, far beyond the end of the message
			body.set(Layouts.LE_UINT16, 32, (char) 1); // NegotiateContextCount
			body.set(Layouts.LE_UINT16, 36, (char) 0x0311); // the dialect that makes the server look for negotiate contexts
			send(socket, message.toArray(Layouts.BYTE));

			var errorResponse = new PacketHeader(MemorySegment.ofArray(in.readNBytes(in.readInt())).asSlice(0, PacketHeader.STRUCTURE_SIZE));

			Assertions.assertEquals(NTStatus.STATUS_INVALID_PARAMETER, errorResponse.status());
		}
	}

	// a NEGOTIATE request offering no dialect, which the server fails with STATUS_INVALID_PARAMETER while leaving the connection un-negotiated
	private static byte[] negotiateWithoutDialects(long messageId) {
		var header = PacketHeader.builder().command(Command.NEGOTIATE.value()).messageId(messageId).build();
		var message = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE + 36]);
		MemorySegment.copy(header.segment(), 0, message, 0, PacketHeader.STRUCTURE_SIZE);
		message.set(Layouts.LE_UINT16, PacketHeader.STRUCTURE_SIZE, (char) 36);
		return message.toArray(Layouts.BYTE);
	}

	// an SMB2 header followed by a body that consists of nothing but its StructureSize field
	private static byte[] smb2Message(char command) {
		var header = PacketHeader.builder().command(command).build();
		var message = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE + 2]);
		MemorySegment.copy(header.segment(), 0, message, 0, PacketHeader.STRUCTURE_SIZE);
		message.set(Layouts.LE_UINT16, PacketHeader.STRUCTURE_SIZE, (char) 2);
		return message.toArray(Layouts.BYTE);
	}

	// prefixes the message with its length as a 4-byte big-endian transport header
	private static void send(Socket socket, byte[] message) throws IOException {
		byte[] transportHeader = new byte[4];
		MemorySegment.ofArray(transportHeader).set(Layouts.BE_INT32, 0, message.length);
		var out = socket.getOutputStream();
		out.write(transportHeader);
		out.write(message);
		out.flush();
	}
}
