package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;

public record Runtime(Connection connection) {

	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a6fbc502-75a5-42ef-a88c-c67b44817850">Receiving an SMB2 LOGOFF Request</a>
	 */
	public SMB2Message logoff(LogoffRequest request) {
		//TODO Perform actual logoff and free resources

		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.command(Command.LOGOFF.value());
		header.creditResponse((char) 1);
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(0);
		header.sessionId(request.header().sessionId());
		header.status(NTStatus.STATUS_SUCCESS);

		return new LogoffResponse(header.build());
	}
}