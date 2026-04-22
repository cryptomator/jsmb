package org.cryptomator.jsmb.smb2.tree;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 TREE_DISCONNECT Request. Fixed 4-byte structure: {@code StructureSize} = 4 + 2 reserved bytes.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b6b70e4e-5e04-4ada-8e40-8b9cd5f9fadb">2.2.11 SMB2 TREE_DISCONNECT Request</a>
 */
public record TreeDisconnectRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	// Reserved: 2 bytes @ offset 2
}
