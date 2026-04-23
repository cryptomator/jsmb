package org.cryptomator.jsmb;

import org.cryptomator.jsmb.common.MalformedMessageException;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb1.SMB1MessageParser;
import org.cryptomator.jsmb.smb1.SMB1Negotiator;
import org.cryptomator.jsmb.smb1.SmbComNegotiateRequest;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.LogoffRequest;
import org.cryptomator.jsmb.smb2.NegotiateRequest;
import org.cryptomator.jsmb.smb2.Negotiator;
import org.cryptomator.jsmb.smb2.Runtime;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.smb2.SMB2MessageParser;
import org.cryptomator.jsmb.smb2.Session;
import org.cryptomator.jsmb.smb2.SessionSetupRequest;
import org.cryptomator.jsmb.smb2.SessionSetupResponse;
import org.cryptomator.jsmb.smb2.UnhandledRequest;
import org.cryptomator.jsmb.smb2.create.CloseRequest;
import org.cryptomator.jsmb.smb2.create.CreateHandler;
import org.cryptomator.jsmb.smb2.create.CreateRequest;
import org.cryptomator.jsmb.smb2.create.CreateResponse;
import org.cryptomator.jsmb.smb2.crypto.MessageEncryptor;
import org.cryptomator.jsmb.smb2.crypto.TransformHeader;
import org.cryptomator.jsmb.smb2.info.QueryInfoHandler;
import org.cryptomator.jsmb.smb2.info.QueryInfoRequest;
import org.cryptomator.jsmb.smb2.ioctl.IoctlHandler;
import org.cryptomator.jsmb.smb2.ioctl.IoctlRequest;
import org.cryptomator.jsmb.smb2.query.QueryDirectoryHandler;
import org.cryptomator.jsmb.smb2.query.QueryDirectoryRequest;
import org.cryptomator.jsmb.smb2.tree.TreeConnectHandler;
import org.cryptomator.jsmb.smb2.tree.TreeConnectRequest;
import org.cryptomator.jsmb.smb2.tree.TreeDisconnectRequest;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.AEADBadTagException;
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
	private final Runtime runtime;
	private final IoctlHandler ioctlHandler;
	private final TreeConnectHandler treeConnectHandler;
	private final CreateHandler createHandler;
	private final QueryDirectoryHandler queryDirectoryHandler;
	private final QueryInfoHandler queryInfoHandler;
	private final MessageEncryptor encryptor = new MessageEncryptor();

	public TcpConnection(TcpServer server, Socket socket) {
		this.server = server;
		this.socket = socket;
		this.connection = new Connection(server.global);
		this.negotiator = new Negotiator(server, connection);
		this.runtime = new Runtime(connection);
		this.ioctlHandler = new IoctlHandler(connection);
		this.treeConnectHandler = new TreeConnectHandler(connection);
		this.createHandler = new CreateHandler(connection);
		this.queryDirectoryHandler = new QueryDirectoryHandler(connection);
		this.queryInfoHandler = new QueryInfoHandler(server, connection);
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
				MemorySegment messageSegment = MemorySegment.ofArray(message);

				// 3. if encrypted (SMB2 TRANSFORM_HEADER), decrypt into plaintext:
				boolean requestEncrypted = isTransformHeader(messageSegment);
				if (requestEncrypted) {
					messageSegment = decryptTransform(messageSegment);
				}

				// 4. determine protocol and handle message:
				if (SMB1MessageParser.isSmb1(messageSegment)) {
					handleSmb1Packet(messageSegment);
				} else if (SMB2MessageParser.isSmb2(messageSegment)) {
					handleSmb2Packet(messageSegment, requestEncrypted);
				} else {
					throw new MalformedMessageException("Unknown protocol");
				}
			}
		} catch (EOFException e) {
			LOG.debug("Connection closed");
		} catch (MalformedMessageException | IOException | AEADBadTagException e) {
			LOG.error("Exception while reading packet", e);
		}
	}

	private static boolean isTransformHeader(MemorySegment segment) {
		if (segment.byteSize() < TransformHeader.STRUCTURE_SIZE) {
			return false;
		}
		return segment.get(Layouts.LE_INT32, 0) == TransformHeader.PROTOCOL_ID;
	}

	private MemorySegment decryptTransform(MemorySegment segment) throws MalformedMessageException, AEADBadTagException {
		var header = new TransformHeader(segment.asSlice(0, TransformHeader.STRUCTURE_SIZE));
		var session = connection.sessionTable.get(header.sessionId());
		if (session == null) {
			throw new MalformedMessageException("Encrypted request for unknown session " + header.sessionId());
		}
		byte[] plaintext = encryptor.decrypt(segment, session.decryptionKey);
		return MemorySegment.ofArray(plaintext);
	}

	private void handleSmb1Packet(MemorySegment segment) throws MalformedMessageException {
		var msg = SMB1MessageParser.parse(segment);
		var response = switch (msg) {
			case SmbComNegotiateRequest request -> new SMB1Negotiator(server, connection).negotiate(request);
			default -> throw new MalformedMessageException("Command not implemented: " + msg.command());
		};
		writeWire(response.serialize());
	}

	private void handleSmb2Packet(MemorySegment segment, boolean requestEncrypted) throws MalformedMessageException {
		int offset = 0;
		int nextCommand;
		FileId chainedFileId = null;
		do {
			var msg = SMB2MessageParser.parse(segment.asSlice(offset));
			if (msg instanceof FileIdCarrying msgWithFile && chainedFileId != null && msg.header().hasFlag(SMB2Message.Flags.RELATED_OPERATIONS)) {
				msgWithFile.substituteFileIdIfSentinel(chainedFileId);
			}
			var response = switch (msg) {
				case NegotiateRequest request -> negotiator.negotiate(request);
				case SessionSetupRequest request -> negotiator.sessionSetup(request);
				case LogoffRequest request -> runtime.logoff(request);
				case IoctlRequest request -> ioctlHandler.handle(request);
				case TreeConnectRequest request -> treeConnectHandler.connect(request);
				case TreeDisconnectRequest request -> treeConnectHandler.disconnect(request);
				case CreateRequest request -> createHandler.create(request);
				case CloseRequest request -> createHandler.close(request);
				case QueryDirectoryRequest request -> queryDirectoryHandler.query(request);
				case QueryInfoRequest request -> queryInfoHandler.query(request);
				case UnhandledRequest request -> {
					LOG.debug("Command 0x{} not implemented, replying STATUS_NOT_SUPPORTED", Integer.toHexString(request.header().command()));
					yield ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
				}
				default -> throw new MalformedMessageException("Unexpected SMB2 message type: " + msg.getClass().getSimpleName());
			};
			if (response instanceof CreateResponse cr) {
				chainedFileId = cr.fileId();
			}
			var signed = sign(msg, response);
			writeWire(maybeEncrypt(signed, requestEncrypted));
			nextCommand = msg.header().nextCommand();
			offset += nextCommand;
		} while (nextCommand != 0);
	}

	/**
	 * Encrypts {@code response} iff any of MS-SMB2 3.3.4.1.4's clauses apply:
	 * <ul>
	 *   <li>the request was itself encrypted (even if {@code Session.EncryptData} is false), or</li>
	 *   <li>{@code Session.EncryptData} is true (and the command is not {@code NEGOTIATE} or {@code SESSION_SETUP}).</li>
	 * </ul>
	 */
	private byte[] maybeEncrypt(SMB2Message response, boolean requestEncrypted) {
		byte[] plain = response.serialize();
		var command = Command.valueOf(response.header().command());
		// NEGOTIATE and SESSION_SETUP responses are never encrypted, per MS-SMB2 3.3.4.1.4
		if (command == Command.NEGOATIATE || command == Command.SESSION_SETUP) {
			return plain;
		}
		var session = connection.sessionTable.get(response.header().sessionId());
		if (session == null || session.encryptionKey == null) {
			// no session keys available — can't encrypt even if we wanted to
			return plain;
		}
		if (requestEncrypted) {
			return encryptor.encrypt(plain, session.encryptionKey, session.sessionId);
		}
		if (!session.encryptData) {
			return plain;
		}
		return encryptor.encrypt(plain, session.encryptionKey, session.sessionId);
	}

	private void writeWire(byte[] bytes) {
		try {
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

	private SMB2Message sign(SMB2Message request, SMB2Message response) {
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
	 * <blockquote>
	 * <p>[...] For all other responses being signed the server
	 * MUST provide <b>Channel.SigningKey</b> by looking up the <b>Channel</b> in <b>Session.ChannelList</b>,
	 * where the connection matches the <b>Channel.Connection</b>.</p>
	 * </blockquote>
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
