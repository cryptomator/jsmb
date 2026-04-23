package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 QUERY_INFO Response. Fixed portion is 8 bytes; {@link #STRUCTURE_SIZE} is 9 per spec.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f">2.2.38 SMB2 QUERY_INFO Response</a>
 */
public record QueryInfoResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 9;
	public static final int FIXED_PORTION_SIZE = 8;

	public QueryInfoResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public QueryInfoResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}

	public void outputBufferOffset(char offset) {
		segment.set(Layouts.LE_UINT16, 2, offset);
	}

	public void outputBufferLength(int length) {
		segment.set(Layouts.LE_INT32, 4, length);
	}

	/**
	 * Appends {@code buffer} as the response's variable tail and stamps the offset + length fields.
	 */
	public QueryInfoResponse withOutputBuffer(byte[] buffer) {
		var fixed = segment.asSlice(0, FIXED_PORTION_SIZE);
		var combined = MemorySegments.concat(fixed, MemorySegment.ofArray(buffer));
		var updated = new QueryInfoResponse(header, combined);
		updated.outputBufferOffset((char) (PacketHeader.STRUCTURE_SIZE + FIXED_PORTION_SIZE));
		updated.outputBufferLength(buffer.length);
		return updated;
	}
}
