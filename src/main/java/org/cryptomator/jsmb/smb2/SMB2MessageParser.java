package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.MalformedMessageException;
import org.cryptomator.jsmb.smb2.ioctl.IoctlRequest;
import org.cryptomator.jsmb.smb2.tree.TreeConnectRequest;
import org.cryptomator.jsmb.smb2.tree.TreeDisconnectRequest;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public class SMB2MessageParser {

	public static boolean isSmb2(MemorySegment segment) {
		if (segment.byteSize() < 66) { // 64 header + 2 structure size
			return false;
		} else {
			int protocolId = segment.get(Layouts.LE_INT32, 0);
			return protocolId == SMB2Message.PROTOCOL_ID;
		}
	}

	public static SMB2Message parse(MemorySegment segment) {
		if (!isSmb2(segment)) {
			throw new MalformedMessageException("Not a SMB2 message");
		}
		var headerSegment = segment.asSlice(0, PacketHeader.STRUCTURE_SIZE);
		var bodySegment = segment.asSlice(PacketHeader.STRUCTURE_SIZE);
		var header = new PacketHeader(headerSegment);
		try {
			return switch (Command.valueOf(header.command())) {
				case NEGOATIATE -> new NegotiateRequest(header, bodySegment);
				case SESSION_SETUP -> new SessionSetupRequest(header, bodySegment);
				case LOGOFF -> new LogoffRequest(header, bodySegment);
				case IOCTL -> new IoctlRequest(header, bodySegment);
				case TREE_CONNECT -> new TreeConnectRequest(header, bodySegment);
				case TREE_DISCONNECT -> new TreeDisconnectRequest(header, bodySegment);
				default -> new UnhandledRequest(header, bodySegment);
			};
		} catch (IllegalArgumentException e) {
			// Command.valueOf throws for an entirely unknown opcode — treat the same as unhandled so
			// the dispatcher can respond with STATUS_NOT_SUPPORTED instead of killing the connection.
			return new UnhandledRequest(header, bodySegment);
		}
	}
}
