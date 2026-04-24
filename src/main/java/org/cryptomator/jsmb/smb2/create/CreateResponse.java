package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.List;

/**
 * SMB2 CREATE Response. Fixed portion is 88 bytes; {@link #STRUCTURE_SIZE} is 89 per spec.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927">2.2.14 SMB2 CREATE Response</a>
 */
public record CreateResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 89;
	public static final int FIXED_PORTION_SIZE = 88;

	public static final int CREATE_ACTION_SUPERSEDED = 0;
	public static final int CREATE_ACTION_OPENED = 1;
	public static final int CREATE_ACTION_CREATED = 2;
	public static final int CREATE_ACTION_OVERWRITTEN = 3;

	public CreateResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public CreateResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}

	public void oplockLevel(byte level) {
		segment.set(Layouts.BYTE, 2, level);
	}

	public void flags(byte flags) {
		segment.set(Layouts.BYTE, 3, flags);
	}

	public void createAction(int action) {
		segment.set(Layouts.LE_INT32, 4, action);
	}

	public void creationTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 8, fileTime);
	}

	public void lastAccessTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 16, fileTime);
	}

	public void lastWriteTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 24, fileTime);
	}

	public void changeTime(long fileTime) {
		segment.set(Layouts.LE_INT64, 32, fileTime);
	}

	public void allocationSize(long size) {
		segment.set(Layouts.LE_INT64, 40, size);
	}

	public void endOfFile(long size) {
		segment.set(Layouts.LE_INT64, 48, size);
	}

	public void fileAttributes(int attributes) {
		segment.set(Layouts.LE_INT32, 56, attributes);
	}

	public void fileId(FileId fileId) {
		fileId.writeTo(segment.asSlice(64, FileId.SIZE));
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(64, FileId.SIZE));
	}

	public void createContextsOffset(int offset) {
		segment.set(Layouts.LE_INT32, 80, offset);
	}

	public void createContextsLength(int length) {
		segment.set(Layouts.LE_INT32, 84, length);
	}

	/**
	 * Returns a new response with {@code contexts} appended past the fixed portion. Each context's {@code Next} field is rewritten to the stride to
	 * the following context (0 on the last); inter-context 8-byte alignment padding is inserted as required by MS-SMB2 2.2.14.
	 * callers are responsible for already having written the other fixed-portion fields (they're copied verbatim).
	 *
	 * @param contexts the contexts to append in order. Empty returns the receiver unchanged.
	 * @throws IllegalStateException if create contexts have already been appended to this response
	 */
	public CreateResponse withCreateContexts(List<CreateContext> contexts) {
		if (contexts.isEmpty()) {
			return this;
		}
		if (segment.get(Layouts.LE_INT32, 84) != 0) {
			throw new IllegalStateException("createContexts can only be created once.");
		}

		int[] strides = new int[contexts.size()];
		int total = 0;
		for (int i = 0; i < contexts.size(); i++) {
			int size = (int) contexts.get(i).segment().byteSize();
			boolean last = i == contexts.size() - 1;
			strides[i] = last ? size : size + (8 - size % 8) % 8;
			total += strides[i];
		}

		var combined = MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE + total]);
		combined.asSlice(0, FIXED_PORTION_SIZE).copyFrom(segment);

		int pos = FIXED_PORTION_SIZE;
		for (int i = 0; i < contexts.size(); i++) {
			var ctxSeg = contexts.get(i).segment();
			int size = (int) ctxSeg.byteSize();
			combined.asSlice(pos, size).copyFrom(ctxSeg);
			boolean last = i == contexts.size() - 1;
			combined.set(Layouts.LE_INT32, pos, last ? 0 : strides[i]);
			pos += strides[i];
		}

		var result = new CreateResponse(header, combined);
		result.createContextsOffset(PacketHeader.STRUCTURE_SIZE + FIXED_PORTION_SIZE);
		result.createContextsLength(total);
		return result;
	}
}
