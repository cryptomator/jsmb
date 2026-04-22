package org.cryptomator.jsmb.smb2.tree;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 TREE_CONNECT Response. Fixed portion is 16 bytes; {@link #STRUCTURE_SIZE} is 16 per spec.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-4fa0-828b-66ef2c91b6c4">2.2.10 SMB2 TREE_CONNECT Response</a>
 */
public record TreeConnectResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 16;

	public static final byte SHARE_TYPE_DISK = 0x01;
	public static final byte SHARE_TYPE_PIPE = 0x02;
	public static final byte SHARE_TYPE_PRINT = 0x03;

	public TreeConnectResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public TreeConnectResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
	}

	public void shareType(byte shareType) {
		segment.set(Layouts.BYTE, 2, shareType);
	}

	public void shareFlags(int shareFlags) {
		segment.set(Layouts.LE_INT32, 4, shareFlags);
	}

	public void capabilities(int capabilities) {
		segment.set(Layouts.LE_INT32, 8, capabilities);
	}

	public void maximalAccess(int maximalAccess) {
		segment.set(Layouts.LE_INT32, 12, maximalAccess);
	}
}
