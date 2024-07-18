package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.TcpServer;
import org.cryptomator.jsmb.asn1.NegTokenInit2;
import org.cryptomator.jsmb.common.SMBMessage;
import org.cryptomator.jsmb.common.SMBStatus;
import org.cryptomator.jsmb.ntlm.NtlmNegotiateMessage;
import org.cryptomator.jsmb.smb2.negotiate.*;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.WinFileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Processes the SMB 2 negotiation request and returns the negotiation response.
 * @param server
 * @param connection
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1">Receiving an SMB2 NEGOTIATE Request</a>
 */
public record Negotiator(TcpServer server, Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(Negotiator.class);

	public SMBMessage negotiate(NegotiateRequest request) {
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
		connection.serverSecurityMode = (short) (SecurityMode.SIGNING_ENABLED | request.securityMode() & SecurityMode.SIGNING_REQUIRED);
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

		// SMB2_ENCRYPTION_CAPABILITIES TODO
		connection.cipherId = 0; // not yet supported

		// SMB2_COMPRESSION_CAPABILITIES TODO
		connection.compressionIds = new short[0]; // not yet supported

		// SMB2_RDMA_TRANSFORM_CAPABILITIES TODO
		connection.RDMATransformIds = new short[0]; // not yet supported

		// SMB2_SIGNING_CAPABILITIES TODO

		// SMB2_TRANSPORT_CAPABILITIES TODO

		// create response
		var header = PacketHeader.builder();
		header.creditCharge((short) 0);
		header.status(SMBStatus.STATUS_SUCCESS);
		header.command(Command.NEGOATIATE.value());
		header.creditResponse((short) 1);
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(0);
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
		contexts.add(EncryptionCapabilities.build((short) 0)); // indicate no common cipher TODO: eventually support encryption, also setting connection.serverCapabilities |= SMB2_GLOBAL_CAP_ENCRYPTION
		// SMB2_COMPRESSION_CAPABILITIES
		contexts.add(CompressionCapabilities.build(new short[]{CompressionCapabilities.ALG_NONE}, CompressionCapabilities.FLAG_NONE)); // compression not supported
		// SMB2_RDMA_TRANSFORM_CAPABILITIES
		contexts.add(RDMATransformCapabilities.build(new short[]{RDMATransformCapabilities.TRANSFORM_NONE})); // rdma transform not supported
		// SMB2_SIGNING_CAPABILITIES
		contexts.add(SigningCapabilities.build(SigningCapabilities.HMAC_SHA256)); // TODO use alg from request
		// SMB2_TRANSPORT_CAPABILITIES
		contexts.add(TransportCapabilities.build(0)); // no transport level security

		// gss token:
		var mechToken = NtlmNegotiateMessage.create("jSMB"); // TODO make this configurable
		var gssToken = NegTokenInit2.create(mechToken.segment().toArray(Layouts.BYTE));

		// finalize response:
		response = response.withSecurityBuffer(gssToken).withNegotiateContexts(contexts);

		// update preauth hash
		connection.preauthIntegrityHashValue = preAuthHashAlgorithm.compute(Bytes.concat(connection.preauthIntegrityHashValue, response.serialize()));

		return response;
	}

	private byte[] genSalt() {
		try {
			var salt = new byte[16];
			SecureRandom.getInstanceStrong().nextBytes(salt);
			return salt;
		} catch (NoSuchAlgorithmException e) {
			// Every implementation of the Java platform is required to support at least one strong SecureRandom implementation.
			throw new IllegalStateException("No strong SecureRandom available", e);
		}
	}

}
