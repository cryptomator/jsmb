package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * A SMB2 LOGOFF Request
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/abdc4ea9-52df-480e-9a36-34f104797d2c">SMB2 LOGOFF Request Specification</a>
 */
public record LogoffRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0); //Should always be 4
	}

	//Reserved: 2 bytes @ offset 2
}