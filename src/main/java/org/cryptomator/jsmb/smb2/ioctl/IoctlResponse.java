package org.cryptomator.jsmb.smb2.ioctl;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 IOCTL Response. Fixed portion is 48 bytes; {@link #STRUCTURE_SIZE} is 49 per spec.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d7cfb98e-6a79-4c44-b429-9da8c98dce21">2.2.32 SMB2 IOCTL Response</a>
 */
public record IoctlResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 49;
	public static final int FIXED_PORTION_SIZE = 48;

	public IoctlResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public IoctlResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}

	public void ctlCode(int ctlCode) {
		segment.set(Layouts.LE_INT32, 4, ctlCode);
	}

	public void fileId(byte[] fileId) {
		if (fileId.length != 16) {
			throw new IllegalArgumentException("FileId must be 16 bytes");
		}
		segment.asSlice(8, 16).copyFrom(MemorySegment.ofArray(fileId));
	}

	public void inputOffset(int offset) {
		segment.set(Layouts.LE_INT32, 24, offset);
	}

	public void inputCount(int count) {
		segment.set(Layouts.LE_INT32, 28, count);
	}

	public void outputOffset(int offset) {
		segment.set(Layouts.LE_INT32, 32, offset);
	}

	public void outputCount(int count) {
		segment.set(Layouts.LE_INT32, 36, count);
	}

	public void flags(int flags) {
		segment.set(Layouts.LE_INT32, 40, flags);
	}

	public IoctlResponse withOutputBuffer(byte[] buffer) {
		var fixed = segment.asSlice(0, FIXED_PORTION_SIZE);
		var combined = MemorySegments.concat(fixed, MemorySegment.ofArray(buffer));
		var updated = new IoctlResponse(header, combined);
		if (buffer.length > 0) {
			updated.outputOffset(PacketHeader.STRUCTURE_SIZE + FIXED_PORTION_SIZE);
			updated.outputCount(buffer.length);
		}
		return updated;
	}
}
