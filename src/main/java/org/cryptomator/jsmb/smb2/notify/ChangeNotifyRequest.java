package org.cryptomator.jsmb.smb2.notify;

import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 CHANGE_NOTIFY Request. 32-byte fixed structure. jSMB does not track filesystem change
 * notifications; the handler responds with {@code STATUS_NOT_SUPPORTED}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c">2.2.35 SMB2 CHANGE_NOTIFY Request</a>
 */
public record ChangeNotifyRequest(PacketHeader header, MemorySegment segment) implements SMB2Message, FileIdCarrying {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public char flags() {
		return segment.get(Layouts.LE_UINT16, 2);
	}

	public int outputBufferLength() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(8, FileId.SIZE));
	}

	public void fileId(FileId fileId) {
		fileId.writeTo(segment.asSlice(8, FileId.SIZE));
	}

	public int completionFilter() {
		return segment.get(Layouts.LE_INT32, 24);
	}
}
