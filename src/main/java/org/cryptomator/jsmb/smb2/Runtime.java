package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.echo.EchoRequest;
import org.cryptomator.jsmb.smb2.echo.EchoResponse;
import org.cryptomator.jsmb.smb2.notify.ChangeNotifyRequest;

public record Runtime(Connection connection) {

	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a6fbc502-75a5-42ef-a88c-c67b44817850">Receiving an SMB2 LOGOFF Request</a>
	 */
	public SMB2Message logoff(LogoffRequest request) {
		//TODO Perform actual logoff and free resources

		return new LogoffResponse(buildResponseHeader(request, Command.LOGOFF, 0, NTStatus.STATUS_SUCCESS));
	}

	/**
	 * Responds with a 4-byte ECHO response. The server is expected to ack regardless of session / tree state.
	 *
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fa23e613-2768-49e5-aa68-97c4bba72379">3.3.5.19 Receiving an SMB2 ECHO Request</a>
	 */
	public SMB2Message echo(EchoRequest request) {
		return new EchoResponse(buildResponseHeader(request, Command.ECHO, request.header().treeId(), NTStatus.STATUS_SUCCESS));
	}

	/**
	 * Responds with {@code STATUS_NOT_SUPPORTED}. jSMB does not track filesystem change notifications; the
	 * error response keeps compatible clients (Finder, Explorer) from tearing down the connection over an
	 * unanswered watch request.
	 *
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ae4bff0e-0e83-4a46-87f5-12553359eea5">3.3.5.18 Receiving an SMB2 CHANGE_NOTIFY Request</a>
	 */
	public SMB2Message changeNotify(ChangeNotifyRequest request) {
		return ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
	}

	private PacketHeader buildResponseHeader(SMB2Message request, Command command, int treeId, int status) {
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.command(command.value());
		header.creditResponse((char) 1);
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(treeId);
		header.sessionId(request.header().sessionId());
		header.status(status);
		return header.build();
	}
}
