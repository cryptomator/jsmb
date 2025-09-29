package org.cryptomator.jsmb;

import org.cryptomator.jsmb.common.MalformedMessageException;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.common.SMBMessage;
import org.cryptomator.jsmb.smb1.SMB1MessageParser;
import org.cryptomator.jsmb.smb1.SMB1Negotiator;
import org.cryptomator.jsmb.smb1.SmbComNegotiateRequest;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.NegotiateRequest;
import org.cryptomator.jsmb.smb2.Negotiator;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.smb2.SMB2MessageParser;
import org.cryptomator.jsmb.smb2.Session;
import org.cryptomator.jsmb.smb2.SessionSetupRequest;
import org.cryptomator.jsmb.smb2.SessionSetupResponse;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.Socket;
import java.util.Arrays;
import java.util.Objects;

import static org.cryptomator.jsmb.smb2.negotiate.GlobalCapabilities.SMB2_GLOBAL_CAP_ENCRYPTION;

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
			writeResponse(sign(msg, response));
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

	private SMBMessage sign(SMB2Message request, SMB2Message response) {
		var sessionId = response.header().sessionId();
		var session = connection.sessionTable.get(sessionId);
		assert (sessionId == 0) == (session == null);
		if (shouldSign(request, response, session)) {
			assert Objects.equals(connection.dialect, "3.1.1");
			return response.sign(selectKey(response, session), connection);
		}
		return response;
	}

	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7">Signing the Message</a>
	 */
	private boolean shouldSign(SMB2Message request, SMB2Message response, @Nullable Session session) {
		var signed = !Arrays.equals(request.header().signature(), new byte[16]);
		var sessionId = response.header().sessionId();
		var treeId = response.header().treeId();

		assert signed == request.header().hasFlag(SMB2Message.Flags.SIGNED);
		assert (sessionId == 0) == (session == null);
		if (signed && sessionId != 0 && treeId == 0 && session.signingRequired) {
			return true;
		}
		if (signed && sessionId != 0 && treeId != 0 && session.signingRequired && (!connection.global.encryptData || ((connection.clientCapabilities & SMB2_GLOBAL_CAP_ENCRYPTION) == 0))) {
			return true;
		}
		if (signed && !response.header().hasFlag(SMB2Message.Flags.ASYNC_COMMAND)) {
			return true;
		}
		return false;
	}

	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7">Signing the Message</a>
	 */
	private byte[] selectKey(SMB2Message response, Session session) {
		if (connection.dialect.startsWith("3.")) {
			if (response instanceof SessionSetupResponse && response.header().status() != NTStatus.STATUS_SUCCESS) {
				return session.signingKey;
			}
			return channelSigningKey(session);
		}
		return session.sessionKey;
	}

	/**
	 * Provides the {@code Channel.SigningKey} for signing a response.
	 *
	 * @apiNote This method implements the following specification from
	 * <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7">Signing the Message:</a>
	 * <i>
	 * <p>[...] For all other responses being signed the server
	 * MUST provide <b>Channel.SigningKey</b> by looking up the <b>Channel</b> in <b>Session.ChannelList</b>,
	 * where the connection matches the <b>Channel.Connection</b>.</p>
	 * </i>
	 * @implNote The current implementation of this method depends on two simplifications:
	 * <ul>
	 *     <li>
	 *         {@code Negotiator.gssAuthenticate()} doesn't accept {@link SessionSetupRequest SessionSetupRequests} with
	 *         {@link SessionSetupRequest#FLAG_BINDING} set.</br>
	 *         Therefore the value of {@code Channel.SigningKey} is always equal to {@link Session#signingKey}</br>
	 *         See: <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654">Handling GSS-API Authentication (step 9)</a>
	 *     </li>
	 *     <li>
	 *         {@code Channel} is not implemented and therefore the value of {@code Channel.SigningKey}
	 *         is the same for all packets of this session.
	 *     </li>
	 * </ul>
	 * As a result this method will always return {@link Session#signingKey}.
	 */
	private byte[] channelSigningKey(Session session) {
		return session.signingKey;
	}
}
