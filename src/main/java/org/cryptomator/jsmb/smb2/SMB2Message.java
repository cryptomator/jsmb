package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.SMBMessage;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * A SMB 2 Message
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4">SMB2 Packet Header Specification</a>
 */
public interface SMB2Message extends SMBMessage {

	int PROTOCOL_ID = 0x424D53FE; // 0xFE S M B

	interface Flags {
		int SERVER_TO_REDIR = 0x00000001;
		int ASYNC_COMMAND = 0x00000002;
		int RELATED_OPERATIONS = 0x00000004;
		int SIGNED = 0x00000008;
		int PRIORITY_MASK = 0x00000070;
		int DFS_OPERATIONS = 0x10000000;
		int REPLAY_OPERATION = 0x20000000;
	}

	PacketHeader header();

	MemorySegment segment();

	default byte[] serialize() {
		return Bytes.concat(header().segment().toArray(Layouts.BYTE), segment().toArray(Layouts.BYTE));
	}

}
