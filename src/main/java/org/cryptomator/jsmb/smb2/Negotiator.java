package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Server;
import org.cryptomator.jsmb.asn1.NegTokenInit2;
import org.cryptomator.jsmb.asn1.NegTokenResp;
import org.cryptomator.jsmb.asn1.NegotiationToken;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.common.NTStatusException;
import org.cryptomator.jsmb.ntlmv2.NtlmSession;
import org.cryptomator.jsmb.smb2.crypto.NistSP800108KDF;
import org.cryptomator.jsmb.smb2.negotiate.CompressionCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.EncryptionCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.GlobalCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.NegotiateContext;
import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.RDMATransformCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.SecurityMode;
import org.cryptomator.jsmb.smb2.negotiate.SigningCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.TransportCapabilities;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.UInt16;
import org.cryptomator.jsmb.util.WinFileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import static org.cryptomator.jsmb.smb2.negotiate.GlobalCapabilities.SMB2_GLOBAL_CAP_ENCRYPTION;

/**
 * Processes the SMB 2 negotiation request and returns the negotiation response.
 * @param server
 * @param connection
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1">Receiving an SMB2 NEGOTIATE Request</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e545352b-9f2b-4c5e-9350-db46e4f6755e">Receiving an SMB2 SESSION_SETUP Request</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c083583f-1a8f-4afe-a742-6ee08ffeb8cf">NTLM Over SMB</a>
 */
public record Negotiator(Server server, Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(Negotiator.class);

	public SMB2Message negotiate(NegotiateRequest request) {
		if (connection.negotiateDialect != 0xFFFF) {
			// TODO disconnect without replying as per spec
			throw new UnsupportedOperationException("Disconnect not yet implemented");
		}
		if (request.dialectCount() == 0) {
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		}
		if (!request.supportsDialect(Dialects.SMB3_1_1)) {
			return ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
		}
		connection.clientGuid = request.clientGuid();
		connection.clientCapabilities = request.capabilities();
		connection.clientDialects = request.dialects();
		connection.shouldSign = (request.securityMode() & SecurityMode.SIGNING_REQUIRED) != 0;
		connection.dialect = "3.1.1";
		connection.negotiateDialect = Dialects.SMB3_1_1;
		connection.clientSecurityMode = request.securityMode();
		connection.supportsMultiCredit = true;
		connection.serverSecurityMode = (char) (SecurityMode.SIGNING_ENABLED | (connection.global.requireMessageSigning ? SecurityMode.SIGNING_REQUIRED : 0));
		connection.serverCapabilities = GlobalCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU;
		LOG.debug("Client supports SMB 3.1.1");

		// SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		var preauth = request.negotiateContext(PreauthIntegrityCapabilities.class); // 3.1.1 MUST include this
		connection.preauthIntegrityHashId = preauth.hashAlgorithms()[0];
		if (!HashAlgorithm.isSupported(connection.preauthIntegrityHashId)) {
			return ErrorResponse.create(request, NTStatus.STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
		}
		var preAuthHashAlgorithm = HashAlgorithm.lookup(connection.preauthIntegrityHashId);
		connection.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(connection.preauthIntegrityHashValue, request.serialize()));

		// Per MS-SMB2 3.3.5.4, each optional 3.1.1 negotiate context is processed iff the server-wide
		// Is<Feature>Supported flag is TRUE; otherwise the server MUST ignore the request context. The
		// response MUST include a matching context iff the request context was processed.

		// SMB2_ENCRYPTION_CAPABILITIES
		var requestedEncryptionCapabilities = request.negotiateContext(EncryptionCapabilities.class);
		boolean processedEncryptionCapabilities = connection.global.isEncryptionSupported && requestedEncryptionCapabilities != null;
		if (processedEncryptionCapabilities) {
			var offered = UInt16.toSet(requestedEncryptionCapabilities.ciphers());
			// prefer AES-256-GCM, fall back to AES-128-GCM (the AEAD ciphers we know we can encrypt/decrypt with the JDK)
			if (offered.contains(EncryptionCapabilities.AES_256_GCM)) {
				connection.cipherId = EncryptionCapabilities.AES_256_GCM;
			} else if (offered.contains(EncryptionCapabilities.AES_128_GCM)) {
				connection.cipherId = EncryptionCapabilities.AES_128_GCM;
			} else {
				connection.cipherId = EncryptionCapabilities.NO_COMMON_CIPHER;
			}
		}

		// SMB2_COMPRESSION_CAPABILITIES
		var requestedCompressionCapabilities = request.negotiateContext(CompressionCapabilities.class);
		boolean processedCompressionCapabilities = connection.global.isCompressionSupported && requestedCompressionCapabilities != null;
		if (processedCompressionCapabilities) {
			// TODO intersect requestedCompressionCapabilities.compressionAlgorithms() with our supported set,
			//  populate connection.compressionIds; honour the FLAG_CHAINED bit and set connection.supportsChainedCompression.
			throw new UnsupportedOperationException("Compression not implemented — Global.isCompressionSupported must stay false until it is");
		}

		// SMB2_RDMA_TRANSFORM_CAPABILITIES
		var requestedRDMATransformCapabilities = request.negotiateContext(RDMATransformCapabilities.class);
		boolean processedRDMATransformCapabilities = connection.global.isRDMATransformSupported && requestedRDMATransformCapabilities != null;
		if (processedRDMATransformCapabilities) {
			// TODO intersect the client's RDMATransformIds with our supported set and populate connection.RDMATransformIds.
			throw new UnsupportedOperationException("RDMA transforms not implemented — Global.isRDMATransformSupported must stay false until they are");
		}

		// SMB2_SIGNING_CAPABILITIES
		var requestedSigningCapabilities = request.negotiateContext(SigningCapabilities.class);
		boolean processedSigningCapabilities = connection.global.isSigningCapabilitiesSupported && requestedSigningCapabilities != null;
		if (processedSigningCapabilities) {
			connection.signingAlgorithmId = UInt16.stream(requestedSigningCapabilities.signingAlgorithms()).anyMatch(c -> c == SigningCapabilities.Algorithm.AES_GMAC.getValue())
					? SigningCapabilities.Algorithm.AES_GMAC
					: SigningCapabilities.Algorithm.AES_CMAC;
		}

		// SMB2_TRANSPORT_CAPABILITIES
		var requestedTransportCapabilities = request.negotiateContext(TransportCapabilities.class);
		boolean processedTransportCapabilities = connection.global.isTransportCapabilitiesSupported && requestedTransportCapabilities != null;
		if (processedTransportCapabilities) {
			// TODO for QUIC transports: set connection.acceptTransportSecurity iff DisableEncryptionOverSecureTransport
			//  is true AND the client set SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY in the Flags field.
			throw new UnsupportedOperationException("Transport capabilities not implemented — Global.isTransportCapabilitiesSupported must stay false until they are");
		}

		// create response
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.status(NTStatus.STATUS_SUCCESS);
		header.command(Command.NEGOTIATE.value());
		header.creditResponse((char) 1);
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(0);
		header.sessionId(0L);
		var response = new NegotiateResponse(header.build());
		response.securityMode(connection.serverSecurityMode);
		response.dialectRevision(Dialects.SMB3_1_1);
		response.serverGuid(server.guid);
		response.capabilities(connection.serverCapabilities);
		response.maxTransactSize(connection.maxTransactSize);
		response.maxReadSize(connection.maxReadSize);
		response.maxWriteSize(connection.maxWriteSize);
		response.systemTime(WinFileTime.now());
		response.serverStartTime(0); // as per spec

		// MS-SMB2 3.3.5.4 "Building a NegotiateContextList": each optional context is emitted iff the server processed the matching request context.
		// Preauth is the one unconditional entry (spec-mandated for 3.1.1).
		List<NegotiateContext> contexts = new ArrayList<>();
		// SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		var salt = genSalt();
		contexts.add(PreauthIntegrityCapabilities.build(connection.preauthIntegrityHashId, salt));
		// SMB2_ENCRYPTION_CAPABILITIES — echoed even with CipherId=0 (NO_COMMON_CIPHER), per spec, so the client can tell "encryption unsupported" from "no common cipher".
		if (processedEncryptionCapabilities) {
			contexts.add(EncryptionCapabilities.build(connection.cipherId));
		}
		// SMB2_COMPRESSION_CAPABILITIES — emitted iff we processed the request context. Per spec, when Connection.CompressionIds is empty the response MUST advertise CompressionAlgorithms={NONE}.
		if (processedCompressionCapabilities) {
			var algs = connection.compressionIds.length == 0
					? new char[]{CompressionCapabilities.ALG_NONE}
					: connection.compressionIds;
			var flags = connection.supportsChainedCompression
					? CompressionCapabilities.FLAG_CHAINED
					: CompressionCapabilities.FLAG_NONE;
			contexts.add(CompressionCapabilities.build(algs, flags));
		}
		// SMB2_RDMA_TRANSFORM_CAPABILITIES — emitted iff processed; empty Connection.RDMATransformIds means "no common transform", and per spec the wire response is RDMATransformIds={TRANSFORM_NONE}.
		if (processedRDMATransformCapabilities) {
			var transforms = connection.RDMATransformIds.length == 0
					? new char[]{RDMATransformCapabilities.TRANSFORM_NONE}
					: connection.RDMATransformIds;
			contexts.add(RDMATransformCapabilities.build(transforms));
		}
		// SMB2_SIGNING_CAPABILITIES
		if (processedSigningCapabilities) {
			assert connection.signingAlgorithmId != null : "Never null if a SigningCapabilities NegotiateContext was processed";
			contexts.add(SigningCapabilities.build(connection.signingAlgorithmId.getValue()));
		}
		// SMB2_TRANSPORT_CAPABILITIES — emitted iff processed. Flags reflect Connection.AcceptTransportSecurity.
		if (processedTransportCapabilities) {
			int flags = connection.acceptTransportSecurity ? TransportCapabilities.ACCEPT_TRANSPORT_LEVEL_SECURITY : 0;
			contexts.add(TransportCapabilities.build(flags));
		}

		// gss token:
		var gssToken = NegTokenInit2.createNtlmOnly();

		// finalize response:
		response = response.withSecurityBuffer(gssToken).withNegotiateContexts(contexts);

		// update preauth hash
		connection.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(connection.preauthIntegrityHashValue, response.serialize()));

		// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1 makes two provisions regarding SMB2_GLOBAL_CAP_ENCRYPTION:
		// 1) Response.Capabilities must contain the flag iff (Connection.Dialect is 3.0 or 3.0.2) and [...].
		// 2) Connection.ServerCapabilities [which is set by Response.Capabilities] must additionally contain the flag if Connection.CipherId is not NO_COMMON_CIPHER [for uses such as "§3.3.5.2.11 Verifying the Tree Connect"].
		if (connection.cipherId != EncryptionCapabilities.NO_COMMON_CIPHER) {
			connection.serverCapabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;
		}

		return response;
	}

	public SMB2Message sessionSetup(SessionSetupRequest request) {
		var global = connection.global;
		assert connection.dialect != null;

		// connection.dialect should only be "3.1.1" at this point, but the spec's steps 1 and 2 only apply to dialects "3.0" and "3.0.2" — so check the flag and fail if it's set but the dialect is 3.1.x.
		var dialect3x = connection.dialect.startsWith("3.");
		if (global.encryptData && global.rejectUnencryptedAccess && !dialect3x) { //Step 1
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}

		assert dialect3x;
		if (global.rejectUnencryptedAccess && (connection.clientCapabilities & SMB2_GLOBAL_CAP_ENCRYPTION) == 0) { //Step 2
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}
		final Session session;
		if (request.header().sessionId() == 0L) { //Step 3
			//See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea10b7ae-b053-4e4c-ab31-a48f7d0a79af
			session = Session.create(connection);
			Thread.currentThread().setName("Session-" + session.sessionId);
			session.state = Session.State.IN_PROGRESS;
			session.preauthIntegrityHashValue = connection.preauthIntegrityHashValue;
			return gssAuthenticate(request, session);
		}

		//Step 4
		if (/* dialect3x && */ global.isMultiChannelCapable && (request.flags() & SessionSetupRequest.FLAG_BINDING) != 0) {
			// TODO implement according to step 4:
			// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e545352b-9f2b-4c5e-9350-db46e4f6755e
			throw new UnsupportedOperationException("multi channel not yet supported");
		} else if (!global.isMultiChannelCapable && (request.flags() & SessionSetupRequest.FLAG_BINDING) != 0) {
			return ErrorResponse.create(request, NTStatus.STATUS_REQUEST_NOT_ACCEPTED);
		} else {
			// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b495e2da-8711-4772-b292-453be0394b49
			// The server MUST look up the Session in Connection.SessionTable by using the SessionId in the SMB2 header of the request.
			// If SessionId is not found in Connection.SessionTable, the server MUST fail the request with STATUS_USER_SESSION_DELETED.
			session = connection.sessionTable.get(request.header().sessionId());
			if (session == null) {
				return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
			}
		}
		assert session != null;
		if (session.state == Session.State.EXPIRED) { //Step 5
			//See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ecc02fb-0e60-4cba-afeb-f13100a6e65e
			session.state = Session.State.IN_PROGRESS;
			session.securityContext = null;
			return gssAuthenticate(request, session); //TODO Handle reauthentication in gssAuthenticate
		} else if (session.state == Session.State.VALID) { //Step 6
			//See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ecc02fb-0e60-4cba-afeb-f13100a6e65e
			return gssAuthenticate(request, session); //TODO Handle reauthentication in gssAuthenticate
		} else { //Step 7
			return gssAuthenticate(request, session);
		}
	}

	//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654
	private SMB2Message gssAuthenticate(SessionSetupRequest request, Session session) {
		assert session.connection == connection;
		if ((request.flags() & SessionSetupRequest.FLAG_BINDING) != 0) {
			//Please mind TcpConnection#channelSigningKey
			throw new UnsupportedOperationException("SMB2_SESSION_FLAG_BINDING not yet supported");
		}
		// create response
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.command(Command.SESSION_SETUP.value());
		header.creditResponse((char) 1);
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(0);
		header.sessionId(session.sessionId);

		try {
			// MS-SMB2 delegates the security buffer to GSS-API (§3.3.5.5.3 "Handling GSS-API
			// Authentication"). Whether the GSS layer accepts a raw NTLMSSP NEGOTIATE_MESSAGE in place of
			// a SPNEGO-wrapped one is an implementation detail of Windows SSPI / the GSS stack — not a
			// behaviour mandated by MS-SMB2 itself. In practice the Linux kernel cifs client with
			// `sec=ntlmssp` and Samba rely on servers accepting both, so we mirror that: peek at the
			// first 8 bytes for the NTLMSSP signature and skip the SPNEGO unwrap/wrap when present. Both
			// paths feed the same NtlmSession state machine.
			var securityBuffer = request.securityBuffer();
			boolean rawNtlm = isRawNtlmssp(securityBuffer);
			byte[] inboundNtlm = rawNtlm ? securityBuffer : NegotiationToken.parse(securityBuffer).token();

			switch (session.ntlmSession) {
				case NtlmSession.Initial s -> {
					var awaitingAuthentication = s.negotiate(inboundNtlm);
					byte[] outboundSecurityBuffer = rawNtlm
							? awaitingAuthentication.serverChallenge()
							: NegTokenResp.acceptIncomplete(awaitingAuthentication.serverChallenge()).negTokenResp().serialize();
					header.status(NTStatus.STATUS_MORE_PROCESSING_REQUIRED);
					var response = new SessionSetupResponse(header.build());
					session.ntlmSession = awaitingAuthentication;

					var fullResponse = response.withSecurityBuffer(outboundSecurityBuffer);
					var preAuthHashAlgorithm = HashAlgorithm.lookup(connection.preauthIntegrityHashId);
					session.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(session.preauthIntegrityHashValue, request.serialize()));
					session.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(session.preauthIntegrityHashValue, fullResponse.serialize()));
					return fullResponse;
				}
				case NtlmSession.AwaitingAuthentication s -> {
					var preAuthHashAlgorithm = HashAlgorithm.lookup(connection.preauthIntegrityHashId);
					session.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(session.preauthIntegrityHashValue, request.serialize()));

					// NTLMv2 validates by recomputing the response hash from (password, user, domain). If the client
					// sent a different user or domain than the one this server was started with, the hash mismatches
					// and authenticate() throws AuthenticationFailedException — no explicit user-lookup needed.
					var creds = connection.global.credentials;
					var authenticated = s.authenticate(inboundNtlm, creds.user(), creds.password(), creds.domain());
					header.status(NTStatus.STATUS_SUCCESS);
					header.creditResponse((char) 8192);
					// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654
					session.ntlmSession = authenticated;
					session.sessionKey = authenticated.exportedSessionKey(); // step 6
					session.fullSessionKey = session.sessionKey;
					session.signingKey = NistSP800108KDF.withHmacSha256(session.sessionKey, "SMBSigningKey\0".getBytes(StandardCharsets.US_ASCII), session.preauthIntegrityHashValue, 16); // step 7
					session.applicationKey = NistSP800108KDF.withHmacSha256(session.sessionKey, "SMBAppKey\0".getBytes(StandardCharsets.US_ASCII), session.preauthIntegrityHashValue, 16); // step 8
					int cipherKeyLength = switch (connection.cipherId) {
						case EncryptionCapabilities.AES_256_CCM, EncryptionCapabilities.AES_256_GCM -> 32;
						default -> 16;
					};
					session.encryptionKey = NistSP800108KDF.withHmacSha256(session.sessionKey, "SMBS2CCipherKey\0".getBytes(StandardCharsets.US_ASCII), session.preauthIntegrityHashValue, cipherKeyLength); // step 11
					session.decryptionKey = NistSP800108KDF.withHmacSha256(session.sessionKey, "SMBC2SCipherKey\0".getBytes(StandardCharsets.US_ASCII), session.preauthIntegrityHashValue, cipherKeyLength); // step 11
					session.encryptData = connection.global.encryptData && connection.cipherId != EncryptionCapabilities.NO_COMMON_CIPHER; // step 10
					if (connection.global.debugEncryption) {
						logSessionKeys(session);
					}
					var response = new SessionSetupResponse(header.build());
					if (session.encryptData) {
						response.sessionFlags(SessionSetupResponse.SMB2_SESSION_FLAG_ENCRYPT_DATA);
					}
					// Raw NTLMSSP has no completion token — an empty SecurityBuffer alongside STATUS_SUCCESS
					// is the correct ack. SPNEGO peers get the usual NegTokenResp{accept_completed}.
					byte[] outboundSecurityBuffer = rawNtlm
							? new byte[0]
							: NegTokenResp.acceptCompleted().negTokenResp().serialize();
					response = response.withSecurityBuffer(outboundSecurityBuffer);
					assert Objects.equals(connection.dialect, "3.1.1");
					return response.sign(session.signingKey, connection); // step 12
				}
				case NtlmSession.Authenticated _ -> throw new IllegalStateException("Session already authenticated");
			}
		} catch (IllegalArgumentException e) {
			// Malformed SPNEGO token / un-parseable NTLMSSP blob — respond with STATUS_INVALID_PARAMETER
			// rather than letting the exception tear down the connection-handling thread.
			LOG.debug("Malformed security blob in SESSION_SETUP", e);
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		} catch (NTStatusException e) {
			// TODO log?
			return ErrorResponse.create(request, e.status);
		}
	}

	/** MS-NLMP 2.2.1 {@code Signature}: every NTLMSSP message begins with the 8-byte magic {@code "NTLMSSP\0"}. */
	private static final byte[] NTLMSSP_MAGIC = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

	private static boolean isRawNtlmssp(byte[] blob) {
		if (blob.length < NTLMSSP_MAGIC.length) return false;
		for (int i = 0; i < NTLMSSP_MAGIC.length; i++) {
			if (blob[i] != NTLMSSP_MAGIC[i]) return false;
		}
		return true;
	}

	private byte[] genSalt() {
		try {
			var salt = new byte[32]; // same as win 10 and later
			SecureRandom.getInstanceStrong().nextBytes(salt);
			return salt;
		} catch (NoSuchAlgorithmException e) {
			// Every implementation of the Java platform is required to support at least one strong SecureRandom implementation.
			throw new IllegalStateException("No strong SecureRandom available", e);
		}
	}

	/**
	 * Emits the session id and derived key material at {@code INFO} so packet captures can be
	 * decrypted in Wireshark (<em>Preferences → Protocols → SMB2 → Decryption keys</em>). Only
	 * invoked when the server was started with {@code Config.DEBUG_ENCRYPTION} in its flag set — otherwise keys never
	 * touch the log.
	 * <p>
	 * Wireshark accepts lines of the form
	 * {@code <SessionId>,<SessionKey>,<ServerInKey>,<ServerOutKey>}
	 * where {@code ServerInKey} is the server's decryption key (C2S) and {@code ServerOutKey} is its
	 * encryption key (S2C) — all hex, no {@code 0x} prefix. The session id must be in
	 * <strong>little-endian</strong> wire order (it's parsed as a byte sequence, not a number); the
	 * human-readable summary line keeps the big-endian rendering that Wireshark's packet-details
	 * view shows for the same field.
	 *
	 * @implNote This method logs secret key material. Gate the call on {@code Global.debugEncryption}.
	 */
	private static void logSessionKeys(Session session) {
		if (!LOG.isInfoEnabled()) return;
		var hex = HexFormat.of();
		var sessionIdBigEndian = String.format("%016x", session.sessionId);
		var sessionIdLittleEndian = String.format("%016x", Long.reverseBytes(session.sessionId));
		LOG.info("""
				SMB2 session 0x{} established — derived keys (paste the Wireshark line into Preferences → Protocols → SMB2 → Decryption keys):
				  SessionKey     = {}
				  SigningKey     = {}
				  EncryptionKey  = {}  (S2C, server→client)
				  DecryptionKey  = {}  (C2S, client→server)
				  ApplicationKey = {}
				  Wireshark line: {},{},{},{}""",
				sessionIdBigEndian,
				hex.formatHex(session.sessionKey),
				hex.formatHex(session.signingKey),
				hex.formatHex(session.encryptionKey),
				hex.formatHex(session.decryptionKey),
				hex.formatHex(session.applicationKey),
				sessionIdLittleEndian,
				hex.formatHex(session.sessionKey),
				hex.formatHex(session.decryptionKey),
				hex.formatHex(session.encryptionKey));
	}

}
