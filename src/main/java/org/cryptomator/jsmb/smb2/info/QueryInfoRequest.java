package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 QUERY_INFO Request. Fixed portion is 40 bytes; {@link #structureSize()} is 41 per the spec
 * convention (variable-length structures declare {@code FixedPortionSize + 1}).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/05391f4e-b5e8-4d8e-b0d5-1c4fdd26dc74">2.2.37 SMB2 QUERY_INFO Request</a>
 */
public record QueryInfoRequest(PacketHeader header, MemorySegment segment) implements SMB2Message, FileIdCarrying {

	/** {@code SMB2_0_INFO_FILE} — the request is for file-level info (MS-FSCC 2.4). */
	public static final byte INFO_TYPE_FILE = 0x01;
	/** {@code SMB2_0_INFO_FILESYSTEM} — the request is for filesystem-level info (MS-FSCC 2.5). */
	public static final byte INFO_TYPE_FILESYSTEM = 0x02;
	/** {@code SMB2_0_INFO_SECURITY} — the request is for a security descriptor. */
	public static final byte INFO_TYPE_SECURITY = 0x03;
	/** {@code SMB2_0_INFO_QUOTA} — the request is for a quota record. */
	public static final byte INFO_TYPE_QUOTA = 0x04;

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public byte infoType() {
		return segment.get(Layouts.BYTE, 2);
	}

	public byte fileInfoClass() {
		return segment.get(Layouts.BYTE, 3);
	}

	public int outputBufferLength() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public char inputBufferOffset() {
		return segment.get(Layouts.LE_UINT16, 8);
	}

	public int inputBufferLength() {
		return segment.get(Layouts.LE_INT32, 12);
	}

	public int additionalInformation() {
		return segment.get(Layouts.LE_INT32, 16);
	}

	public int flags() {
		return segment.get(Layouts.LE_INT32, 20);
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(24, FileId.SIZE));
	}

	public void fileId(FileId fileId) {
		fileId.writeTo(segment.asSlice(24, FileId.SIZE));
	}
}
