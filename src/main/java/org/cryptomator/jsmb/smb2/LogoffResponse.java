package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * A SMB2 LOGOFF Response
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7539feb4-6fbb-4996-81ac-06863bb1a89e">SMB2 LOGOFF Response Specification</a>
 */
public record LogoffResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 4;

	public LogoffResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
		segment.set(Layouts.LE_UINT16, 2, (char) 0); //Reserved
	}

	public LogoffResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
	}
}