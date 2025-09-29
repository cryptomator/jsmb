package org.cryptomator.jsmb.smb1;

import org.cryptomator.jsmb.TcpServer;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.common.SMBMessage;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.Dialects;
import org.cryptomator.jsmb.smb2.NegotiateResponse;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.smb2.negotiate.GlobalCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.SecurityMode;
import org.cryptomator.jsmb.util.WinFileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles an SMB1 NEGOTIATE request by responding with an SMB2 NEGOTIATE response or an "unsupported dialect" SMB1 response
 *
 * @param server The server on behalf of which this negotiator acts
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b99264a6-7520-4563-adaf-fc4fdf7d5a1b">Negotiation protocol example</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/26646611-6a0f-4549-9c82-f9343e750a81">Receiving an SMB_COM_NEGOTIATE</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/bcd6d594-017b-47fc-8742-b7d847791783">SMB 2.1 or SMB 3.x Support</a>
 */
public record SMB1Negotiator(TcpServer server, Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(SMB1Negotiator.class);

	public SMBMessage negotiate(SmbComNegotiateRequest request) {
		if (connection.negotiateDialect != 0xFFFF) {
			// TODO disconnect without replying as per spec
		}
		if (request.dialects().contains("SMB 2.???")) {
			LOG.info("SMB1: Upgrading to SMB2...");
			connection.supportsMultiCredit = true;
			var header = PacketHeader.builder();
			header.creditCharge((char) 0);
			header.status(NTStatus.STATUS_SUCCESS);
			header.command(Command.NEGOATIATE.value());
			header.creditResponse((char) 1);
			header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
			header.nextCommand(0);
			header.messageId(0);
			header.treeId(0);
			header.sessionId(0L);
			var response = new NegotiateResponse(header.build());
			response.securityMode((char) (SecurityMode.SIGNING_ENABLED | (connection.global.requireMessageSigning ? SecurityMode.SIGNING_REQUIRED : 0)));
			response.dialectRevision(Dialects.SMB2_WILDCARD);
			response.serverGuid(server.guid);
			response.capabilities(GlobalCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU);
			response.maxTransactSize(connection.maxTransactSize);
			response.maxReadSize(connection.maxReadSize);
			response.maxWriteSize(connection.maxWriteSize);
			response.systemTime(WinFileTime.now());
			response.serverStartTime(0);
			return response;
		} else {
			LOG.warn("Attempted to connect with dialects: {}", String.join("; ", request.dialects()));
			return SmbComNegotiateResponse.unsupportedDialectResponse();
		}
	}
}
