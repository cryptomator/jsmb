package org.cryptomator.jsmb.smb2.tree;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/**
 * SMB2 TREE_CONNECT Request. Fixed portion is 8 bytes; {@link #structureSize()} is 9 per the spec
 * convention (variable-length structures declare {@code FixedPortionSize + 1}).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/832d2130-22e8-4afb-aafd-b30bb0901798">2.2.9 SMB2 TREE_CONNECT Request</a>
 */
public record TreeConnectRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public char flags() {
		return segment.get(Layouts.LE_UINT16, 2);
	}

	public char pathOffset() {
		return segment.get(Layouts.LE_UINT16, 4);
	}

	public char pathLength() {
		return segment.get(Layouts.LE_UINT16, 6);
	}

	/**
	 * @return the {@code Buffer} contents decoded as UTF-16LE — typically a path of the form {@code \\server\share}
	 */
	public String path() {
		int offset = pathOffset() - PacketHeader.STRUCTURE_SIZE;
		int length = pathLength();
		if (length == 0) return "";
		byte[] bytes = segment.asSlice(offset, length).toArray(Layouts.BYTE);
		return new String(bytes, StandardCharsets.UTF_16LE);
	}
}
