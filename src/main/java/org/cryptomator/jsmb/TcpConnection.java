package org.cryptomator.jsmb;

import org.cryptomator.jsmb.common.DisconnectException;
import org.cryptomator.jsmb.common.MalformedMessageException;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb1.SMB1MessageParser;
import org.cryptomator.jsmb.smb1.SMB1Negotiator;
import org.cryptomator.jsmb.smb1.SmbComNegotiateRequest;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.CompoundChain;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.Dialects;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.LogoffRequest;
import org.cryptomator.jsmb.smb2.NegotiateRequest;
import org.cryptomator.jsmb.smb2.Negotiator;
import org.cryptomator.jsmb.smb2.RequestVerifier;
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
import org.cryptomator.jsmb.smb2.echo.CancelRequest;
import org.cryptomator.jsmb.smb2.echo.EchoRequest;
import org.cryptomator.jsmb.smb2.notify.ChangeNotifyRequest;
import org.cryptomator.jsmb.smb2.crypto.MessageEncryptor;
import org.cryptomator.jsmb.smb2.crypto.TransformHeader;
import org.cryptomator.jsmb.smb2.info.QueryInfoHandler;
import org.cryptomator.jsmb.smb2.info.QueryInfoRequest;
import org.cryptomator.jsmb.smb2.info.SetInfoHandler;
import org.cryptomator.jsmb.smb2.info.SetInfoRequest;
import org.cryptomator.jsmb.smb2.io.FlushRequest;
import org.cryptomator.jsmb.smb2.io.ReadHandler;
import org.cryptomator.jsmb.smb2.io.ReadRequest;
import org.cryptomator.jsmb.smb2.io.WriteHandler;
import org.cryptomator.jsmb.smb2.io.WriteRequest;
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
import java.util.List;
import java.util.Objects;

import static org.cryptomator.jsmb.smb2.negotiate.GlobalCapabilities.SMB2_GLOBAL_CAP_ENCRYPTION;

class TcpConnection implements Runnable {

	private static final Logger LOG = LoggerFactory.getLogger(TcpConnection.class);

	private final Server server;
	private final Socket socket;
	private final Connection connection;
	private final RequestVerifier requestVerifier;
	private final Negotiator negotiator;
	private final Runtime runtime;
	private final IoctlHandler ioctlHandler;
	private final TreeConnectHandler treeConnectHandler;
	private final CreateHandler createHandler;
	private final QueryDirectoryHandler queryDirectoryHandler;
	private final QueryInfoHandler queryInfoHandler;
	private final SetInfoHandler setInfoHandler;
	private final ReadHandler readHandler;
	private final WriteHandler writeHandler;
	private final MessageEncryptor encryptor = new MessageEncryptor();

	public TcpConnection(Server server, Socket socket) {
		this.server = server;
		this.socket = socket;
		this.connection = new Connection(server.global);
		this.requestVerifier = new RequestVerifier(connection);
		this.negotiator = new Negotiator(server, connection);
		this.runtime = new Runtime(connection);
		this.ioctlHandler = new IoctlHandler(connection);
		this.treeConnectHandler = new TreeConnectHandler(connection);
		this.createHandler = new CreateHandler(connection);
		this.queryDirectoryHandler = new QueryDirectoryHandler(connection);
		this.queryInfoHandler = new QueryInfoHandler(server, connection);
		this.setInfoHandler = new SetInfoHandler(connection);
		this.readHandler = new ReadHandler(connection);
		this.writeHandler = new WriteHandler(connection);
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

				// Cap the NBSS-declared length before allocating. A malicious client could claim the full
				// 24-bit NBSS range (~16 MiB) on every frame and force us to hold that much per connection.
				// 2× maxTransactSize gives headroom for legitimate compound chains without opening that door.
				int maxMessageSize = Math.max(2 * connection.maxTransactSize, 64 * 1024);
				if (messageSize < 0 || messageSize > maxMessageSize) {
					throw new MalformedMessageException("NBSS frame length " + messageSize + " exceeds cap " + maxMessageSize);
				}

				// 2. read SMB or SMB2 message:
				byte[] message = new byte[messageSize];
				if (in.readNBytes(message, 0, messageSize) != messageSize) {
					throw new EOFException();
				}
				MemorySegment messageSegment = MemorySegment.ofArray(message);

				// 3. if encrypted (SMB2 TRANSFORM_HEADER), decrypt into plaintext:
				Long transformSessionId = null;
				if (isTransformHeader(messageSegment)) {
					transformSessionId = new TransformHeader(messageSegment.asSlice(0, TransformHeader.STRUCTURE_SIZE)).sessionId();
					messageSegment = decryptTransform(messageSegment);
				}

				// 4. determine protocol and handle message:
				if (SMB1MessageParser.isSmb1(messageSegment)) {
					handleSmb1Packet(messageSegment);
				} else if (SMB2MessageParser.isSmb2(messageSegment)) {
					handleSmb2Packet(messageSegment, transformSessionId);
				} else {
					throw new MalformedMessageException("Unknown protocol");
				}
			}
		} catch (EOFException e) {
			LOG.debug("Connection closed");
		} catch (DisconnectException e) {
			LOG.warn("Disconnecting client: {}", e.getMessage());
		} catch (MalformedMessageException | IOException | AEADBadTagException e) {
			LOG.error("Exception while reading packet", e);
		} finally {
			// Handling Loss of a Connection: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eb5bfe99-47fe-4e87-8e87-08a084dcefb6
			// A copy, as removing a session alters the table. No session spans several connections, as there are no channels.
			List.copyOf(connection.sessionTable.values()).forEach(Session::remove);
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
		// an SMB_COM_NEGOTIATE counts as MessageId 0, which a repeated one therefore can't get past
		if (!connection.commandSequenceWindow.consume(0L, 1)) {
			throw new DisconnectException("SMB_COM_NEGOTIATE after MessageId 0 got used");
		}
		var response = switch (msg) {
			case SmbComNegotiateRequest request -> new SMB1Negotiator(server, connection).negotiate(request);
			default -> throw new MalformedMessageException("Command not implemented: " + msg.command());
		};
		if (response instanceof SMB2Message) {
			// the wildcard response to a multi-protocol negotiate grants the one credit that the client's SMB2 NEGOTIATE needs
			connection.commandSequenceWindow.grant(1);
		}
		writeWire(response.serialize());
	}

	// transformSessionId: the SessionId of the SMB2 TRANSFORM_HEADER the packet arrived in, or null if it arrived unencrypted
	private void handleSmb2Packet(MemorySegment segment, @Nullable Long transformSessionId) throws MalformedMessageException {
		boolean requestEncrypted = transformSessionId != null;
		int offset = 0;
		int nextCommand;
		var chain = new CompoundChain();
		FileId chainedFileId = null;
		do {
			var msg = SMB2MessageParser.parse(segment.asSlice(offset));
			// Verifying the Connection State: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4daf7dce-9f49-4413-99bf-323801c9283d
			if (!(msg instanceof NegotiateRequest) && (connection.negotiateDialect == Dialects.NONE || connection.negotiateDialect == Dialects.SMB2_WILDCARD)) {
				throw new DisconnectException("Request on a connection that hasn't negotiated a dialect yet");
			}
			// Verifying the Sequence Number: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0326f784-0baf-45fd-9687-626859ef5a9b
			// CANCEL carries the MessageId of the request it cancels and consumes none itself.
			int creditCharge = msg.header().creditCharge();
			int consumedCredits = connection.supportsMultiCredit && creditCharge > 0 ? creditCharge : 1;
			int grantedCredits = 0;
			if (!(msg instanceof CancelRequest)) {
				if (!connection.commandSequenceWindow.consume(msg.header().messageId(), consumedCredits)) {
					throw new DisconnectException("MessageId " + msg.header().messageId() + " (credit charge " + creditCharge + ") is not within the command sequence window");
				}
				// Granting Credits to the Client: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46256e72-b361-4d73-ac7d-d47c04b32e4b
				// Asking for no less than the request consumed keeps the client from running dry, whatever it requested and however the request ends.
				// Decided before dispatching, as NEGOTIATE and SESSION_SETUP responses must be final by the time they get hashed for preauth integrity.
				grantedCredits = connection.commandSequenceWindow.grant(Math.max(msg.header().creditRequest(), consumedCredits));
			}
			var sessionId = chain.sessionId(msg);
			var treeId = chain.treeId(msg);
			var rejection = requestVerifier.verify(msg, sessionId, treeId, transformSessionId);
			// Only now make a related request say what it is processed with: its signature had to be verified over the bytes as sent.
			if (msg.header().hasFlag(SMB2Message.Flags.RELATED_OPERATIONS)) {
				if (sessionId != null) {
					msg.header().sessionId(sessionId);
				}
				if (treeId != null) {
					msg.header().treeId(treeId);
				}
				if (msg instanceof FileIdCarrying msgWithFile && chainedFileId != null) {
					msgWithFile.substituteFileIdIfSentinel(chainedFileId);
				}
			}
			// looked up before dispatching, as a LOGOFF response still has to be signed or encrypted with the keys of the session it just removed
			var sessionBefore = sessionId == null ? null : connection.sessionTable.get(sessionId);
			SMB2Message response = rejection.isPresent() ? reject(msg, rejection.getAsInt()) : switch (msg) {
				case NegotiateRequest request -> negotiator.negotiate(request, grantedCredits);
				case SessionSetupRequest request -> negotiator.sessionSetup(request, grantedCredits);
				case LogoffRequest request -> runtime.logoff(request);
				case IoctlRequest request -> ioctlHandler.handle(request);
				case TreeConnectRequest request -> treeConnectHandler.connect(request);
				case TreeDisconnectRequest request -> treeConnectHandler.disconnect(request);
				case CreateRequest request -> createHandler.create(request);
				case CloseRequest request -> createHandler.close(request);
				case QueryDirectoryRequest request -> queryDirectoryHandler.query(request);
				case QueryInfoRequest request -> queryInfoHandler.query(request);
				case SetInfoRequest request -> setInfoHandler.set(request);
				case ReadRequest request -> readHandler.read(request);
				case WriteRequest request -> writeHandler.write(request);
				case FlushRequest request -> writeHandler.flush(request);
				case EchoRequest request -> runtime.echo(request);
				case ChangeNotifyRequest request -> runtime.changeNotify(request);
				case CancelRequest request -> {
					// CANCEL is one-way — no response is emitted for the CANCEL itself. jSMB has no async
					// requests in flight, so there is nothing to interrupt; log and drop.
					LOG.debug("CANCEL messageId={} (no async in flight)", request.header().messageId());
					yield null;
				}
				case UnhandledRequest request -> {
					LOG.debug("Command 0x{} not implemented, replying STATUS_NOT_SUPPORTED", Integer.toHexString(request.header().command()));
					yield ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
				}
				default -> throw new MalformedMessageException("Unexpected SMB2 message type: " + msg.getClass().getSimpleName());
			};
			chain.processed(msg, response);
			// Advance the chain cursor before the null-response guard so `continue` still makes progress.
			nextCommand = msg.header().nextCommand();
			offset += nextCommand;
			if (response == null) {
				// CANCEL emits no response; later elements of a compound chain still need theirs, so continue.
				continue;
			}
			if (response instanceof CreateResponse cr) {
				chainedFileId = cr.fileId();
			}
			var credited = response.withCredits(msg.header().creditCharge(), (char) grantedCredits);
			var session = sessionOf(credited, sessionBefore);
			var signed = sign(msg, credited, session);
			writeWire(maybeEncrypt(signed, requestEncrypted, session));
		} while (nextCommand != 0);
	}

	// The session whose keys protect a response: the one named in its header (which SESSION_SETUP may just have created) or, if that one is gone by now, the one the request was processed with.
	private @Nullable Session sessionOf(SMB2Message response, @Nullable Session sessionBefore) {
		long sessionId = response.header().sessionId();
		var session = connection.sessionTable.get(sessionId);
		if (session == null && sessionBefore != null && sessionBefore.sessionId == sessionId) {
			return sessionBefore;
		}
		return session;
	}

	private static @Nullable SMB2Message reject(SMB2Message request, int status) {
		if (request instanceof CancelRequest) {
			// CANCEL is one-way, so not even its rejection is answered. An error carrying the MessageId of the request to be cancelled would be mistaken for that request's response.
			return null;
		}
		return ErrorResponse.create(request, status);
	}

	/**
	 * Encrypts {@code response} iff any of MS-SMB2 3.3.4.1.4's clauses apply:
	 * <ul>
	 *   <li>the request was itself encrypted (even if {@code Session.EncryptData} is false), or</li>
	 *   <li>{@code Session.EncryptData} is true (and the command is not {@code NEGOTIATE} or {@code SESSION_SETUP}).</li>
	 * </ul>
	 */
	private byte[] maybeEncrypt(SMB2Message response, boolean requestEncrypted, @Nullable Session session) {
		byte[] plain = response.serialize();
		var command = Command.valueOf(response.header().command());
		// NEGOTIATE and SESSION_SETUP responses are never encrypted, per MS-SMB2 3.3.4.1.4
		if (command == Command.NEGOTIATE || command == Command.SESSION_SETUP) {
			return plain;
		}
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

	private SMB2Message sign(SMB2Message request, SMB2Message response, @Nullable Session session) {
		if (session == null || session.signingKey == null) {
			// Nothing to sign with: the response is not bound to a session, its session is unknown or got removed (e.g. failed logon), or authentication hasn't completed yet.
			return response;
		}
		if (shouldSign(request, response, session)) {
			assert Objects.equals(connection.dialect, "3.1.1");
			return response.sign(selectKey(response, session), connection);
		}
		return response;
	}

	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7">Signing the Message</a>
	 */
	private boolean shouldSign(SMB2Message request, SMB2Message response, Session session) {
		var signed = request.header().hasFlag(SMB2Message.Flags.SIGNED);
		var sessionId = response.header().sessionId();
		var treeId = response.header().treeId();

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
