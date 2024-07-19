package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record PacketHeaderBuilder(MemorySegment segment) {

	public PacketHeaderBuilder {
		segment.set(Layouts.LE_INT32, 0, SMB2Message.PROTOCOL_ID);
		segment.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
	}

	public PacketHeaderBuilder() {
		this(MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]));
	}

	public PacketHeaderBuilder creditCharge(char creditCharge) {
		segment.set(Layouts.LE_UINT16, 6, creditCharge);
		return this;
	}

	public PacketHeaderBuilder status(int status) {
		segment.set(Layouts.LE_INT32, 8, status);
		return this;
	}

	public PacketHeaderBuilder command(char command) {
		segment.set(Layouts.LE_UINT16, 12, command);
		return this;
	}

	public PacketHeaderBuilder creditResponse(char creditResponse) {
		segment.set(Layouts.LE_UINT16, 14, creditResponse);
		return this;
	}

	public PacketHeaderBuilder flags(int flags) {
		segment.set(Layouts.LE_INT32, 16, flags);
		return this;
	}

	public PacketHeaderBuilder nextCommand(int nextCommand) {
		segment.set(Layouts.LE_INT32, 20, nextCommand);
		return this;
	}

	public PacketHeaderBuilder messageId(long messageId) {
		segment.set(Layouts.LE_INT64, 24, messageId);
		return this;
	}

	public PacketHeaderBuilder asyncId(long asyncId) {
		segment.set(Layouts.LE_INT64, 32, asyncId);
		return this;
	}

	public PacketHeaderBuilder treeId(int treeId) {
		segment.set(Layouts.LE_INT32, 36, treeId);
		return this;
	}

	public PacketHeaderBuilder sessionId(long sessionId) {
		segment.set(Layouts.LE_INT64, 40, sessionId);
		return this;
	}

	public PacketHeaderBuilder signature(byte[] signature) {
		segment.asSlice(44, 16).copyFrom(MemorySegment.ofArray(signature));
		return this;
	}

	public PacketHeader build() {
		return new PacketHeader(segment.asReadOnly());
	}

}