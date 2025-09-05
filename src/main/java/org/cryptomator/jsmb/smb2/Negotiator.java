package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.TcpServer;
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
public record Negotiator(TcpServer server, Connection connection) {

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

		// SMB2_ENCRYPTION_CAPABILITIES
		var requestedEncryptionCapabilities = request.negotiateContext(EncryptionCapabilities.class);
		if (requestedEncryptionCapabilities != null) {
			connection.cipherId = UInt16.stream(requestedEncryptionCapabilities.ciphers()).anyMatch(c -> c == EncryptionCapabilities.AES_256_GCM)
					? EncryptionCapabilities.AES_256_GCM
					: EncryptionCapabilities.NO_COMMON_CIPHER;
			if (connection.cipherId != EncryptionCapabilities.NO_COMMON_CIPHER) {
				connection.serverCapabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;
			}
		}

		// SMB2_COMPRESSION_CAPABILITIES TODO
		connection.compressionIds = new char[0]; // not yet supported

		// SMB2_RDMA_TRANSFORM_CAPABILITIES TODO
		connection.RDMATransformIds = new char[0]; // not yet supported

		// SMB2_SIGNING_CAPABILITIES
		var requestedSigningCapabilities = request.negotiateContext(SigningCapabilities.class);
		if (request.negotiateContext(SigningCapabilities.class) != null) {
			connection.signingAlgorithmId = UInt16.stream(requestedSigningCapabilities.signingAlgorithms()).anyMatch(c -> c == SigningCapabilities.AES_GMAC)
					? SigningCapabilities.AES_GMAC
					: SigningCapabilities.AES_CMAC;
		}

		// SMB2_TRANSPORT_CAPABILITIES TODO

		// create response
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.status(NTStatus.STATUS_SUCCESS);
		header.command(Command.NEGOATIATE.value());
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

		List<NegotiateContext> contexts = new ArrayList<>();
		// SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		var salt = genSalt();
		contexts.add(PreauthIntegrityCapabilities.build(connection.preauthIntegrityHashId, salt));
		// SMB2_ENCRYPTION_CAPABILITIES
		if (requestedEncryptionCapabilities != null) {
			contexts.add(EncryptionCapabilities.build(connection.cipherId));
		}
		// SMB2_COMPRESSION_CAPABILITIES
		if (request.negotiateContext(CompressionCapabilities.class) != null) {
			contexts.add(CompressionCapabilities.build(new char[]{CompressionCapabilities.ALG_NONE}, CompressionCapabilities.FLAG_NONE)); // compression not supported
		}
		// SMB2_RDMA_TRANSFORM_CAPABILITIES
		if (request.negotiateContext(RDMATransformCapabilities.class) != null) {
			contexts.add(RDMATransformCapabilities.build(new char[]{RDMATransformCapabilities.TRANSFORM_NONE})); // rdma transform not supported
		}
		// SMB2_SIGNING_CAPABILITIES
		if (request.negotiateContext(SigningCapabilities.class) != null) {
			contexts.add(SigningCapabilities.build(connection.signingAlgorithmId));
		}
		// SMB2_TRANSPORT_CAPABILITIES
		if (request.negotiateContext(TransportCapabilities.class) != null) {
			contexts.add(TransportCapabilities.build(0)); // no transport level security
		}

		// gss token:
		var gssToken = NegTokenInit2.createNtlmOnly();

		// finalize response:
		response = response.withSecurityBuffer(gssToken).withNegotiateContexts(contexts);

		// update preauth hash
		connection.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(connection.preauthIntegrityHashValue, response.serialize()));

		return response;
	}

	public SMB2Message sessionSetup(SessionSetupRequest request) {
		var global = connection.global;
		assert global.encryptData;
		assert global.rejectUnencryptedAccess;
		assert connection.dialect != null;

		//connection.dialect should only be "3.1.1"
		var dialect3x = connection.dialect.startsWith("3.");
		if (/* assertions && */ !dialect3x) { //Step 1
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}

		assert dialect3x;
		if (/* assertions && dialect3x && */ (connection.clientCapabilities & SMB2_GLOBAL_CAP_ENCRYPTION) == 0) { //Step 2
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
			var gssToken = NegotiationToken.parse(request.securityBuffer()); // security buffer MUST contain a GSS output token, see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8b90c335-5a64-4238-9813-84bd734599eb
			switch (session.ntlmSession) {
				case NtlmSession.Initial s -> {
					var awaitingAuthentication = s.negotiate(gssToken.token());
					var negTokenResp = NegTokenResp.acceptIncomplete(awaitingAuthentication.serverChallenge());
					header.status(NTStatus.STATUS_MORE_PROCESSING_REQUIRED);
					var response = new SessionSetupResponse(header.build());
					session.ntlmSession = awaitingAuthentication;

					var fullResponse = response.withSecurityBuffer(negTokenResp.negTokenResp().serialize());
					var preAuthHashAlgorithm = HashAlgorithm.lookup(connection.preauthIntegrityHashId);
					session.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(session.preauthIntegrityHashValue, request.serialize()));
					session.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(session.preauthIntegrityHashValue, fullResponse.serialize()));
					return fullResponse;
				}
				case NtlmSession.AwaitingAuthentication s -> {
					var preAuthHashAlgorithm = HashAlgorithm.lookup(connection.preauthIntegrityHashId);
					session.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(session.preauthIntegrityHashValue, request.serialize()));

					var authenticated = s.authenticate(gssToken.token(), "user", "password", "DOMAIN"); // FIXME hardcoded credentials
					header.status(NTStatus.STATUS_SUCCESS);
					header.creditResponse((char) 8192);
					// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654
					session.ntlmSession = authenticated;
					session.sessionKey = authenticated.exportedSessionKey(); // step 6
					session.fullSessionKey = session.sessionKey;
					session.signingKey = NistSP800108KDF.withHmacSha256(session.sessionKey, "SMBSigningKey\0".getBytes(StandardCharsets.US_ASCII), session.preauthIntegrityHashValue, 16); // step 7
					session.applicationKey = NistSP800108KDF.withHmacSha256(session.sessionKey, "SMBAppKey\0".getBytes(StandardCharsets.US_ASCII), session.preauthIntegrityHashValue, 16); // step 8
					var response = new SessionSetupResponse(header.build()).withSecurityBuffer(NegTokenResp.acceptCompleted().negTokenResp().serialize());
					assert Objects.equals(connection.dialect, "3.1.1");
					return response.sign(session.signingKey, connection); // step 12
				}
				case NtlmSession.Authenticated _ -> throw new IllegalStateException("Session already authenticated");
			}
		} catch (IllegalArgumentException e) {
			// TODO fail with status SEC_E_INVALID_TOKEN
			throw new UnsupportedOperationException("Not yet implemented", e);
		} catch (NTStatusException e) {
			// TODO log?
			return ErrorResponse.create(request, e.status);
		}
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

}
