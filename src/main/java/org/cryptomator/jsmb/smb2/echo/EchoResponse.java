package org.cryptomator.jsmb.smb2.echo;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 ECHO Response. Fixed 4-byte structure (StructureSize + Reserved).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/2abe9b3c-c5ab-417f-bcc3-9ab51f2fce35">2.2.29 SMB2 ECHO Response</a>
 */
public record EchoResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 4;
	public static final int FIXED_PORTION_SIZE = 4;

	public EchoResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public EchoResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}
}
