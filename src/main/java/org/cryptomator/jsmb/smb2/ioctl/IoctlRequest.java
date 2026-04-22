package org.cryptomator.jsmb.smb2.ioctl;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 IOCTL Request. Fixed portion is 56 bytes; {@link #structureSize()} is 57 per the spec convention
 * (variable-length structures declare {@code FixedPortionSize + 1}).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c02ba95a-cd2d-4d13-add4-feeb6302b78b">2.2.31 SMB2 IOCTL Request</a>
 */
public record IoctlRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final int FLAG_IS_FSCTL = 0x00000001;

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

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
