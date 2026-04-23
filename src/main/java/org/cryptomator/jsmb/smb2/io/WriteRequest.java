package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 WRITE Request. Fixed portion is 48 bytes; {@link #structureSize()} is 49 per the spec convention
 * (variable-length structures declare {@code FixedPortionSize + 1}). The payload bytes follow at
 * {@link #dataOffset()} measured from the start of the SMB2 header.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8">2.2.21 SMB2 WRITE Request</a>
 */
public record WriteRequest(PacketHeader header, MemorySegment segment) implements SMB2Message, FileIdCarrying {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public char dataOffset() {
		return segment.get(Layouts.LE_UINT16, 2);
	}

	public int length() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public long offset() {
		return segment.get(Layouts.LE_INT64, 8);
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(16, FileId.SIZE));
	}

	public void fileId(FileId fileId) {
		fileId.writeTo(segment.asSlice(16, FileId.SIZE));
	}

	public int channel() {
		return segment.get(Layouts.LE_INT32, 32);
	}

	public int remainingBytes() {
		return segment.get(Layouts.LE_INT32, 36);
	}

	public char writeChannelInfoOffset() {
		return segment.get(Layouts.LE_UINT16, 40);
	}

	public char writeChannelInfoLength() {
		return segment.get(Layouts.LE_UINT16, 42);
	}

	public int flags() {
		return segment.get(Layouts.LE_INT32, 44);
	}

	/**
	 * The data payload as indicated by {@code DataOffset} (relative to the SMB2 header) and {@link #length()}.
	 * {@code DataOffset} is translated to body-relative by subtracting {@link PacketHeader#STRUCTURE_SIZE}.
	 */
	public MemorySegment data() {
		int bodyRelative = dataOffset() - PacketHeader.STRUCTURE_SIZE;
		return segment.asSlice(bodyRelative, length());
	}
}
