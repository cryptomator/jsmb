package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 CLOSE Response. Fixed 60-byte structure.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0bfe6bc0-4bb6-4f3c-a11a-a0e81a7d94b4">2.2.16 SMB2 CLOSE Response</a>
 */
public record CloseResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 60;

	public CloseResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public CloseResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
	}

	public void flags(char flags) {
		segment.set(Layouts.LE_UINT16, 2, flags);
	}

	public void creationTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 8, fileTime);
	}

	public void lastAccessTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 16, fileTime);
	}

	public void lastWriteTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 24, fileTime);
	}

	public void changeTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 32, fileTime);
	}

	public void allocationSize(long size) {
		segment.set(Layouts.LE_INT64, 40, size);
	}

	public void endOfFile(long size) {
		segment.set(Layouts.LE_INT64, 48, size);
	}

	public void fileAttributes(int attributes) {
		segment.set(Layouts.LE_INT32, 56, attributes);
	}
}
