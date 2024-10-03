package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.TcpServer;
import org.cryptomator.jsmb.asn1.NegTokenInit;
import org.cryptomator.jsmb.asn1.NegTokenInit2;
import org.cryptomator.jsmb.asn1.NegTokenResp;
import org.cryptomator.jsmb.asn1.NegotiationToken;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.common.NTStatusException;
import org.cryptomator.jsmb.ntlmv2.NtlmSession;
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
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.UInt16;
import org.cryptomator.jsmb.util.WinFileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.MemorySegment;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

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
		}
		if (request.dialectCount() == 0) {
			// TODO fail with STATUS_INVALID_PARAMETER
		}
		if (!request.supportsDialect(Dialects.SMB3_1_1)) {
			// TODO fail with STATUS_NOT_SUPPORTED
		}
		connection.clientGuid = request.clientGuid();
		connection.clientCapabilities = request.capabilities();
		connection.clientDialects = request.dialects();
		connection.shouldSign = (request.securityMode() & SecurityMode.SIGNING_REQUIRED) != 0;
		connection.dialect = "3.1.1";
		connection.negotiateDialect = Dialects.SMB3_1_1;
		connection.clientSecurityMode = request.securityMode();
		connection.supportsMultiCredit = true;
		connection.serverSecurityMode = (char) (SecurityMode.SIGNING_ENABLED | request.securityMode() & SecurityMode.SIGNING_REQUIRED);
		connection.serverCapabilities = GlobalCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU;
		LOG.debug("Client supports SMB 3.1.1");

		// SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		var preauth = request.negotiateContext(PreauthIntegrityCapabilities.class); // 3.1.1 MUST include this
		connection.preauthIntegrityHashId = preauth.hashAlgorithms()[0];
		if (!HashAlgorithm.isSupported(connection.preauthIntegrityHashId)) {
			// TODO fail with STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP
		}
		var preAuthHashAlgorithm = HashAlgorithm.lookup(connection.preauthIntegrityHashId);
		connection.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(connection.preauthIntegrityHashValue, request.serialize()));

		// SMB2_ENCRYPTION_CAPABILITIES
		var requestedEncryptionCapabilities = request.negotiateContext(EncryptionCapabilities.class);
		if (requestedEncryptionCapabilities != null) {
			connection.cipherId = UInt16.stream(requestedEncryptionCapabilities.ciphers()).anyMatch(c -> c == EncryptionCapabilities.AES_256_GCM)
					? EncryptionCapabilities.AES_256_GCM
					: EncryptionCapabilities.NO_COMMON_CIPHER;
			// TODO: also set connection.serverCapabilities |= SMB2_GLOBAL_CAP_ENCRYPTION
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
		if (connection.negotiateDialect != Dialects.SMB3_1_1) {
			// TODO fail with STATUS_ACCESS_DENIED as per spec
		}
		if ((connection.clientCapabilities & GlobalCapabilities.SMB2_GLOBAL_CAP_ENCRYPTION) == 0) {
			// TODO disconnect without replying as per spec
		}
		final Session session;
		if (request.header().sessionId() == 0L) {
			session = Session.create(connection);
			Thread.currentThread().setName("Session-" + session.sessionId);
			session.state = Session.State.IN_PROGRESS;
			session.preauthIntegrityHashValue = connection.preauthIntegrityHashValue;
		} else if ((request.flags() & SessionSetupRequest.FLAG_BINDING) != 0) {
			// TODO implement according to step 4:
			// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e545352b-9f2b-4c5e-9350-db46e4f6755e
			throw new UnsupportedOperationException("multi channel not yet supported");
		} else {
			// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b495e2da-8711-4772-b292-453be0394b49
			// The server MUST look up the Session in Connection.SessionTable by using the SessionId in the SMB2 header of the request.
			// If SessionId is not found in Connection.SessionTable, the server MUST fail the request with STATUS_USER_SESSION_DELETED.
			session = connection.sessionTable.get(request.header().sessionId());
			if (session == null) {
				// TODO fail with STATUS_USER_SESSION_DELETED
				throw new UnsupportedOperationException("no idea which session to continue with. according to spec we should fail with STATUS_INVALID_PARAMETER");
			}
		}
		assert session != null;
		if (session.state == Session.State.EXPIRED || session.state == Session.State.VALID) {
			// TODO reauthenticate according to https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ecc02fb-0e60-4cba-afeb-f13100a6e65e
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
			var ntlmMessage = switch (gssToken) {
				case NegTokenInit initToken -> initToken.getMechToken();
				case NegTokenResp responseToken -> responseToken.getResponseToken();
			};
			switch (session.ntlmSession) {
				case NtlmSession.Initial s -> {
					var awaitingAuthentication = s.negotiate(ntlmMessage);
					var negTokenResp = NegTokenResp.acceptIncomplete(awaitingAuthentication.serverChallenge());
					header.status(NTStatus.STATUS_MORE_PROCESSING_REQUIRED);
					var response = new SessionSetupResponse(header.build());
					session.ntlmSession = awaitingAuthentication;
					return response.withSecurityBuffer(negTokenResp.negTokenResp().serialize());
				}
				case NtlmSession.AwaitingAuthentication s -> {
					var authenticated = s.authenticate(ntlmMessage, "user", "password", "domain"); // FIXME hardcoded credentials
					header.status(NTStatus.STATUS_SUCCESS);
					session.ntlmSession = authenticated;
					return new SessionSetupResponse(header.build());
				}
				case NtlmSession.Authenticated _ -> throw new IllegalStateException("Session already authenticated");
			}
		} catch (IllegalArgumentException e) {
			// TODO fail with status SEC_E_INVALID_TOKEN
			throw new UnsupportedOperationException("Not yet implemented", e);
		} catch (NTStatusException e) {
			// TODO log?
			header.status(e.status);
			return new SessionSetupResponse(header.build());
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
