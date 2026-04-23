package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 FLUSH Response. 4-byte fixed structure.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/42f78e6a-e25f-48f5-8f08-b4f1bb4c4fa4">2.2.18 SMB2 FLUSH Response</a>
 */
public record FlushResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 4;
	public static final int FIXED_PORTION_SIZE = 4;

	public FlushResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public FlushResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}
}
