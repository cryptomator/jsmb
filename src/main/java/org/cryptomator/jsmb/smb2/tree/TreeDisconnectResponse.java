package org.cryptomator.jsmb.smb2.tree;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 TREE_DISCONNECT Response. Fixed 4-byte structure (2 bytes {@code StructureSize} + 2 reserved).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4ebef36b-b4c7-4faf-b39e-8a55d0f66b20">2.2.12 SMB2 TREE_DISCONNECT Response</a>
 */
public record TreeDisconnectResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 4;

	public TreeDisconnectResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public TreeDisconnectResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
	}
}
