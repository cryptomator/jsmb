package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.negotiate.NegotiateContext;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.UInt16;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * A SMB 2 NEGOTIATE Request
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5">SMB2 NEGOTIATE Request Specification</a>
 */
public record NegotiateRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	private static final int DIALECTS_OFFSET = 36; // within the body

	@Override
	public boolean isWellFormed() {
		// The negotiate contexts are not looked at here. Whether they exist depends on the dialects, and failing to parse them fails the request just the same.
		return SMB2Message.hasStructure(segment, 36) && DIALECTS_OFFSET + dialectCount() * Character.BYTES <= segment.byteSize();
	}

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0); // should always be 36, regardless of dialects and negotiate contexts
	}

	public char dialectCount() {
		return segment.get(Layouts.LE_UINT16, 2);
	}

	public char securityMode() {
		return segment.get(Layouts.LE_UINT16, 4);
	}

	public int capabilities() {
		return segment.get(Layouts.LE_INT32, 8);
	}

	public UUID clientGuid() {
		long msb = segment.get(Layouts.BE_INT64, 12);
		long lsb = segment.get(Layouts.BE_INT64, 20);
		return new UUID(msb, lsb);
	}

	public int negotiateContextOffset() {
		return segment.get(Layouts.LE_INT32, 28);
	}

	public char negotiateContextCount() {
		return segment.get(Layouts.LE_UINT16, 32);
	}

	public char[] dialects() {
		return segment.asSlice(DIALECTS_OFFSET, dialectCount() * Character.BYTES).toArray(Layouts.LE_UINT16);
	}

	public boolean supportsDialect(char dialect) {
		return UInt16.stream(dialects()).anyMatch(d -> d == dialect);
	}

	/**
	 * @return the negotiate contexts of known types in the order they appear in, duplicates included; contexts of unknown types are left out
	 */
	public List<NegotiateContext> negotiateContexts() {
		if (!supportsDialect(Dialects.SMB3_1_1)) {
			return List.of();
		}

		// NegotiateContextOffset is relative to the beginning of the SMB2 header. An offset outside of the message makes asSlice throw, which fails the request.
		long contextsOffset = Integer.toUnsignedLong(negotiateContextOffset()) - PacketHeader.STRUCTURE_SIZE;
		MemorySegment contextsSegment = segment.asSlice(contextsOffset);
		List<NegotiateContext> result = new ArrayList<>();
		for (int offset = 0, i = 0; i < negotiateContextCount(); i++) {
			var ctxSegment = contextsSegment.asSlice(offset);
			var ctx = NegotiateContext.parse(ctxSegment);
			if (ctx != null) {
				result.add(ctx);
			}
			var ctxSize = 8 + ctxSegment.get(Layouts.LE_UINT16, 2); // header + DataLength
			var paddingSize = (8 - ctxSize % 8) % 8;
			offset += ctxSize + paddingSize;
		}
		return result;
	}

	/**
	 * @param type a type of negotiate context
	 * @param <T>  the type of negotiate context
	 * @return all negotiate contexts of the given type
	 */
	public <T extends NegotiateContext> List<T> negotiateContexts(Class<T> type) {
		return negotiateContexts().stream().filter(type::isInstance).map(type::cast).toList();
	}

	public <T extends NegotiateContext> T negotiateContext(Class<T> type) {
		return negotiateContexts().stream()
				.filter(type::isInstance)
				.map(type::cast)
				.findFirst()
				.orElse(null);
	}

}
