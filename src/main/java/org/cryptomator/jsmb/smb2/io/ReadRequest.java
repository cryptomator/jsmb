package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 READ Request. Fixed portion is 48 bytes; {@link #structureSize()} is 49 per the spec convention
 * (variable-length structures declare {@code FixedPortionSize + 1}).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/320f04f3-1b28-45cd-aaa1-9e5aed810dca">2.2.19 SMB2 READ Request</a>
 */
public record ReadRequest(PacketHeader header, MemorySegment segment) implements SMB2Message, FileIdCarrying {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public byte flags() {
		return segment.get(Layouts.BYTE, 3);
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

	public int minimumCount() {
		return segment.get(Layouts.LE_INT32, 32);
	}

	public int channel() {
		return segment.get(Layouts.LE_INT32, 36);
	}

	public int remainingBytes() {
		return segment.get(Layouts.LE_INT32, 40);
	}

	/**
	 * Offset of the channel-specific buffer, measured from the start of the SMB2 header. Non-zero only
	 * when {@link #channel()} indicates RDMA — ignored on plain TCP transports.
	 */
	public char readChannelInfoOffset() {
		return segment.get(Layouts.LE_UINT16, 44);
	}

	/**
	 * Length of the channel-specific buffer. Non-zero only when {@link #channel()} indicates RDMA.
	 */
	public char readChannelInfoLength() {
		return segment.get(Layouts.LE_UINT16, 46);
	}
}
