package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;

/**
 * A single {@code SMB2_CREATE_CONTEXT} — the tagged, variable-length extras clients and servers exchange in CREATE
 * requests and responses (leases, query-maximal-access, durable-handle hints, etc.).
 *
 * <p>Wire layout (8-byte aligned):
 * <pre>
 * +0  Next         (4)  offset to next context, 0 if last
 * +4  NameOffset   (2)  from start of this context
 * +6  NameLength   (2)
 * +8  Reserved     (2)
 * +10 DataOffset   (2)  from start of this context, 0 if no data
 * +12 DataLength   (4)
 * +16 Name + pad   (NameLength bytes; padding aligns Data to 8-byte boundary)
 *     Data         (DataLength bytes)
 * </pre>
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d">MS-SMB2 2.2.13.2 SMB2_CREATE_CONTEXT Request Values</a>
 */
public record CreateContext(MemorySegment segment) {

	/** {@code "MxAc"} — MS-SMB2 2.2.13.2.5 / 2.2.14.2.5 Query Maximal Access. */
	public static final byte[] NAME_MXAC = {'M', 'x', 'A', 'c'};

	public int next() {
		return segment.get(Layouts.LE_INT32, 0);
	}

	public char nameOffset() {
		return segment.get(Layouts.LE_UINT16, 4);
	}

	public char nameLength() {
		return segment.get(Layouts.LE_UINT16, 6);
	}

	public char dataOffset() {
		return segment.get(Layouts.LE_UINT16, 10);
	}

	public int dataLength() {
		return segment.get(Layouts.LE_INT32, 12);
	}

	public MemorySegment name() {
		return segment.asSlice(nameOffset(), nameLength());
	}

	public MemorySegment data() {
		int off = dataOffset();
		return off == 0 ? MemorySegment.NULL.asSlice(0, 0) : segment.asSlice(off, dataLength());
	}

	public boolean nameEquals(byte[] other) {
		if (nameLength() != other.length) {
			return false;
		}
		return Arrays.equals(name().toArray(Layouts.BYTE), other);
	}

	/**
	 * Builds a standalone {@code SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE} context (32 bytes, no trailing alignment
	 * padding because it's the only / last context in its chain).
	 *
	 * @param queryStatus NTSTATUS from the access check (typically {@code STATUS_SUCCESS}).
	 * @param maximalAccess the access mask granted on the opened handle.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0fe6be15-3a76-4032-9a44-56f846ac6244">MS-SMB2 2.2.14.2.5 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE</a>
	 */
	public static CreateContext mxAcResponse(int queryStatus, int maximalAccess) {
		var seg = MemorySegment.ofArray(new byte[32]);
		seg.set(Layouts.LE_UINT16, 4, (char) 16);  // NameOffset
		seg.set(Layouts.LE_UINT16, 6, (char) 4);   // NameLength
		seg.set(Layouts.LE_UINT16, 10, (char) 24); // DataOffset (16 + 4 Name + 4 pad)
		seg.set(Layouts.LE_INT32, 12, 8);          // DataLength
		seg.asSlice(16, 4).copyFrom(MemorySegment.ofArray(NAME_MXAC));
		seg.set(Layouts.LE_INT32, 24, queryStatus);
		seg.set(Layouts.LE_INT32, 28, maximalAccess);
		return new CreateContext(seg);
	}
}
