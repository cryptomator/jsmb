package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record PacketHeader(MemorySegment segment) {

	public static final char STRUCTURE_SIZE = 64;

	public static PacketHeaderBuilder builder() {
		return new PacketHeaderBuilder();
	}

	public int structureSize() {
		return segment.get(Layouts.LE_UINT16, 4);

	}

	char creditCharge() {
		return segment.get(Layouts.LE_UINT16, 6);
	}

	public int status() {
		return segment.get(Layouts.LE_INT32, 8);
	}

	public char channelSequence() {
		return segment.get(Layouts.LE_UINT16, 8);
	}

	public char command() {
		return segment.get(Layouts.LE_UINT16, 12);
	}

	public char creditRequest() {
		return segment.get(Layouts.LE_UINT16, 14);
	}

	public char creditResponse() {
		return segment.get(Layouts.LE_UINT16, 14);
	}

	public int flags() {
		return segment.get(Layouts.LE_INT32, 16);
	}

	public boolean hasFlag(int flag) {
		return (flags() & flag) == flag;
	}

	public int nextCommand() {
		return segment.get(Layouts.LE_INT32, 20);
	}

	public long messageId() {
		return segment.get(Layouts.LE_INT64, 24);
	}

	public long asyncId() {
		if (hasFlag(SMB2Message.Flags.ASYNC_COMMAND)) {
			return segment.get(Layouts.LE_INT64, 32);
		} else {
			throw new UnsupportedOperationException("Not an async command");
		}
	}

	public int treeId() {
		if (!hasFlag(SMB2Message.Flags.ASYNC_COMMAND)) {
			return segment.get(Layouts.LE_INT32, 36);
		} else {
			throw new UnsupportedOperationException("Not a sync command");
		}
	}

	public long sessionId() {
		return segment.get(Layouts.LE_INT64, 40);
	}

	public byte[] signature() {
		return segment.asSlice(48, 16).toArray(Layouts.BYTE);
	}
}
