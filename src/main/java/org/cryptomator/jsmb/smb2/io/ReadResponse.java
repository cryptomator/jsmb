package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 READ Response. Fixed portion is 16 bytes; {@link #STRUCTURE_SIZE} is 17 per spec.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90">2.2.20 SMB2 READ Response</a>
 */
public record ReadResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 17;
	public static final int FIXED_PORTION_SIZE = 16;

	public ReadResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public ReadResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}

	public void dataOffset(byte offset) {
		segment.set(Layouts.BYTE, 2, offset);
	}

	public void dataLength(int length) {
		segment.set(Layouts.LE_INT32, 4, length);
	}

	public void dataRemaining(int remaining) {
		segment.set(Layouts.LE_INT32, 8, remaining);
	}

	/**
	 * Appends {@code data} as the response's variable tail and stamps DataOffset (relative to the SMB2 header) and
	 * DataLength. Callers should set DataRemaining separately if the client indicated interest via {@code RemainingBytes}.
	 */
	public ReadResponse withData(byte[] data) {
		var combined = MemorySegments.concat(segment.asSlice(0, FIXED_PORTION_SIZE), MemorySegment.ofArray(data));
		var updated = new ReadResponse(header, combined);
		updated.dataOffset((byte) (PacketHeader.STRUCTURE_SIZE + FIXED_PORTION_SIZE));
		updated.dataLength(data.length);
		return updated;
	}
}
