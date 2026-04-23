package org.cryptomator.jsmb.smb2.echo;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 CANCEL Request. Fixed 4-byte structure (StructureSize + Reserved). CANCEL is one-way — no
 * response is emitted for the CANCEL itself; the target async request (if any) is expected to
 * produce a {@code STATUS_CANCELLED} response instead.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/91913fc6-4ec9-4a83-961b-370070067e63">2.2.30 SMB2 CANCEL Request</a>
 */
public record CancelRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}
}
