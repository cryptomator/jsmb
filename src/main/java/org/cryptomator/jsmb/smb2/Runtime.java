package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.MalformedMessageException;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.negotiate.GlobalCapabilities;


//TODO Bad sig: Unset/Set signed flag
//TODO 			0x00000000 at the end
// FLAG POSition
//TODO which bits
//Assert: 3.1 version
public record Runtime(Connection connection) {

	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a6fbc502-75a5-42ef-a88c-c67b44817850">Receiving an SMB2 LOGOFF Request</a>
	 */
	public SMB2Message logoff(LogoffRequest request) {
		//TODO Actually logoff

		//TODO Replace this with something not hacked together
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