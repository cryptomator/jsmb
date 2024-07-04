package org.cryptomator.jsmb.smb1;

import org.cryptomator.jsmb.MalformedMessageException;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public class SMB1MessageParser {

	public static boolean isSmb1(MemorySegment segment) {
		if (segment.byteSize() < 34) { // 32 header + 1 word count + 1 byte count
			return false;
		} else {
			int protocolId = segment.get(Layouts.LE_INT32, 0);
			return protocolId == SMB1Message.PROTOCOL_ID;
		}
	}

	public static SMB1Message parse(MemorySegment segment) {
		if (!isSmb1(segment)) {
			throw new MalformedMessageException("Not a SMB1 message");
		}
		byte command = segment.get(Layouts.BYTE, 4);
		return switch (command) {
			case SmbComNegotiateRequest.COMMAND -> new SmbComNegotiateRequest(segment);
			default -> throw new MalformedMessageException("Unknown command: " + command);
		};
	}
}
