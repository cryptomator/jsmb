package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 SET_INFO Response. Fixed 2-byte structure (StructureSize only).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c4318eb4-bdab-49b7-9352-abd7005c7f19">2.2.40 SMB2 SET_INFO Response</a>
 */
public record SetInfoResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 2;
	public static final int FIXED_PORTION_SIZE = 2;

	public SetInfoResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public SetInfoResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}
}
