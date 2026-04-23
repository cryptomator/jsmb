package org.cryptomator.jsmb.smb2.echo;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 ECHO Request. Fixed 4-byte structure (StructureSize + Reserved).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d939504d-57e2-4c0e-8ad5-1678b6fccca1">2.2.28 SMB2 ECHO Request</a>
 */
public record EchoRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}
}
