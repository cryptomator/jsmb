package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 SET_INFO Request. Fixed portion is 32 bytes; {@link #structureSize()} is 33 per the spec
 * convention (variable-length structures declare {@code FixedPortionSize + 1}). The payload
 * follows at {@link #bufferOffset()} measured from the start of the SMB2 header.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4">2.2.39 SMB2 SET_INFO Request</a>
 */
public record SetInfoRequest(PacketHeader header, MemorySegment segment) implements SMB2Message, FileIdCarrying {

	/** {@code SMB2_0_INFO_FILE} — the request is setting file-level info (MS-FSCC 2.4). */
	public static final byte INFO_TYPE_FILE = 0x01;
	/** {@code SMB2_0_INFO_FILESYSTEM} — the request is setting filesystem-level info (MS-FSCC 2.5). */
	public static final byte INFO_TYPE_FILESYSTEM = 0x02;
	/** {@code SMB2_0_INFO_SECURITY} — the request is setting a security descriptor. */
	public static final byte INFO_TYPE_SECURITY = 0x03;
	/** {@code SMB2_0_INFO_QUOTA} — the request is setting a quota record. */
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

	public int bufferLength() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public char bufferOffset() {
		return segment.get(Layouts.LE_UINT16, 8);
	}

	public int additionalInformation() {
		return segment.get(Layouts.LE_INT32, 12);
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(16, FileId.SIZE));
	}

	public void fileId(FileId fileId) {
		fileId.writeTo(segment.asSlice(16, FileId.SIZE));
	}

	/**
	 * The info payload at {@code BufferOffset} (relative to the SMB2 header) with {@link #bufferLength()} bytes.
	 */
	public MemorySegment buffer() {
		int bodyRelative = bufferOffset() - PacketHeader.STRUCTURE_SIZE;
		return segment.asSlice(bodyRelative, bufferLength());
	}
}
