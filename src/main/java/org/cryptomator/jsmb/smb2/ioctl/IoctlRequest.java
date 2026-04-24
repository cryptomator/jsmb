package org.cryptomator.jsmb.smb2.ioctl;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 IOCTL Request. Fixed portion is 56 bytes; {@link #structureSize()} is 57 per the spec convention
 * (variable-length structures declare {@code FixedPortionSize + 1}).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8">MS-SMB2 2.2.31 SMB2 IOCTL Request</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458">MS-FSCC 2.3 FSCTL Structures</a>
 */
public record IoctlRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	/** When set in {@link #flags()}, {@link #ctlCode()} names an FSCTL (MS-FSCC §2.3) rather than a device IOCTL. */
	public static final int FLAG_IS_FSCTL = 0x00000001;

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	/**
	 * @return the {@link FsctlCode FSCTL code}
	 */
	public int ctlCode() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public byte[] fileId() {
		return segment.asSlice(8, 16).toArray(Layouts.BYTE);
	}

	public int inputOffset() {
		return segment.get(Layouts.LE_INT32, 24);
	}

	public int inputCount() {
		return segment.get(Layouts.LE_INT32, 28);
	}

	public int maxInputResponse() {
		return segment.get(Layouts.LE_INT32, 32);
	}

	public int outputOffset() {
		return segment.get(Layouts.LE_INT32, 36);
	}

	public int outputCount() {
		return segment.get(Layouts.LE_INT32, 40);
	}

	public int maxOutputResponse() {
		return segment.get(Layouts.LE_INT32, 44);
	}

	public int flags() {
		return segment.get(Layouts.LE_INT32, 48);
	}

	public boolean isFsctl() {
		return (flags() & FLAG_IS_FSCTL) != 0;
	}

	public byte[] inputBuffer() {
		int offset = inputOffset();
		int count = inputCount();
		if (count == 0) {
			return new byte[0];
		}
		return segment.asSlice(offset - PacketHeader.STRUCTURE_SIZE, count).toArray(Layouts.BYTE);
	}
}
