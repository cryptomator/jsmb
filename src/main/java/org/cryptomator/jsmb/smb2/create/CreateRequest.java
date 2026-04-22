package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/**
 * SMB2 CREATE Request. Fixed portion is 56 bytes; {@link #structureSize()} is 57 per the spec
 * convention (variable-length structures declare {@code FixedPortionSize + 1}).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997">2.2.13 SMB2 CREATE Request</a>
 */
public record CreateRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public byte requestedOplockLevel() {
		return segment.get(Layouts.BYTE, 3);
	}

	public int impersonationLevel() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public int desiredAccess() {
		return segment.get(Layouts.LE_INT32, 24);
	}

	public int fileAttributes() {
		return segment.get(Layouts.LE_INT32, 28);
	}

	public int shareAccess() {
		return segment.get(Layouts.LE_INT32, 32);
	}

	public int createDisposition() {
		return segment.get(Layouts.LE_INT32, 36);
	}

	public int createOptions() {
		return segment.get(Layouts.LE_INT32, 40);
	}

	public char nameOffset() {
		return segment.get(Layouts.LE_UINT16, 44);
	}

	public char nameLength() {
		return segment.get(Layouts.LE_UINT16, 46);
	}

	public int createContextsOffset() {
		return segment.get(Layouts.LE_INT32, 48);
	}

	public int createContextsLength() {
		return segment.get(Layouts.LE_INT32, 52);
	}

	/**
	 * @return the UTF-16LE Name decoded — path relative to the share root, using backslashes. The
	 *         share root itself is the empty string.
	 */
	public String name() {
		int length = nameLength();
		if (length == 0) return "";
		int offset = nameOffset() - PacketHeader.STRUCTURE_SIZE;
		byte[] bytes = segment.asSlice(offset, length).toArray(Layouts.BYTE);
		return new String(bytes, StandardCharsets.UTF_16LE);
	}
}
