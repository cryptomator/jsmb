package org.cryptomator.jsmb;

import org.cryptomator.jsmb.common.SMBMessage;
import org.cryptomator.jsmb.smb1.SMB1MessageParser;
import org.cryptomator.jsmb.smb1.SMB1Negotiator;
import org.cryptomator.jsmb.smb1.SmbComNegotiateRequest;
import org.cryptomator.jsmb.smb2.*;
import org.cryptomator.jsmb.util.Layouts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.Socket;

class TcpConnection implements Runnable {

	private static final Logger LOG = LoggerFactory.getLogger(TcpConnection.class);

	private final TcpServer server;
	private final Socket socket;
	private final Connection connection;
	private final Negotiator negotiator;

	public TcpConnection(TcpServer server, Socket socket) {
		this.server = server;
		this.socket = socket;
		this.connection = new Connection(server.global);
		this.negotiator = new Negotiator(server, connection);
	}

	@Override
	public void run() {
		try (var in = socket.getInputStream()) {
			byte[] transportHeader = new byte[4];
			var transportHeaderSegment = MemorySegment.ofArray(transportHeader);
			while (!Thread.interrupted()) {
				// 1. determine size of SMB or SMB2 message:
				// see SMB1 https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f906c680-330c-43ae-9a71-f854e24aeee6
				// see SMB2 https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83
				if (in.readNBytes(transportHeader, 0, transportHeader.length) != transportHeader.length) {
					throw new EOFException();
				}
				int messageSize = transportHeaderSegment.get(Layouts.BE_INT32, 0); // "network byte order" is big endian
				assert messageSize < 0x00FFFFFF; // first byte is always 0

				// 2. read SMB or SMB2 message:
				byte[] message = new byte[messageSize];
				if (in.readNBytes(message, 0, messageSize) != messageSize) {
					throw new EOFException();
				}
				var messageSegment = MemorySegment.ofArray(message).asReadOnly();

				// 3. determine protocol and handle message:
				if (SMB1MessageParser.isSmb1(messageSegment)) {
					handleSmb1Packet(messageSegment);
				} else if (SMB2MessageParser.isSmb2(messageSegment)) {
					handleSmb2Packet(messageSegment);
				} else {
					throw new MalformedMessageException("Unknown protocol");
				}
			}
		} catch (EOFException e) {
			LOG.debug("Connection closed");
		} catch (MalformedMessageException | IOException e) {
			LOG.error("Exception while reading packet", e);
		}
	}

	private void handleSmb1Packet(MemorySegment segment) throws MalformedMessageException {
		var msg = SMB1MessageParser.parse(segment);
		var response = switch (msg) {
			case SmbComNegotiateRequest request -> new SMB1Negotiator(server, connection).negotiate(request);
			default -> throw new MalformedMessageException("Command not implemented: " + msg.command());
		};
		writeResponse(response);
	}

	private void handleSmb2Packet(MemorySegment segment) throws MalformedMessageException {
		int nextCommand = 0;
		do {
			var msg = SMB2MessageParser.parse(segment.asSlice(nextCommand));
			var response = switch (msg) {
				case NegotiateRequest request -> negotiator.negotiate(request);
				case SessionSetupRequest request -> negotiator.sessionSetup(request);
				default -> throw new MalformedMessageException("Command not implemented: " + msg.header().command());
			};
			writeResponse(response);
			nextCommand = msg.header().nextCommand();
		} while (nextCommand != 0);
	}

	private void writeResponse(SMBMessage response) {
		try {
			var bytes = response.serialize();
			var out = socket.getOutputStream();
			byte[] transportHeader = new byte[4];
			var transportHeaderSegment = MemorySegment.ofArray(transportHeader);
			transportHeaderSegment.set(Layouts.BE_INT32, 0, bytes.length);
			out.write(transportHeader);
			out.write(bytes);
			out.flush();
		} catch (IOException e) {
			LOG.error("Exception while writing response", e);
		}
	}
}
