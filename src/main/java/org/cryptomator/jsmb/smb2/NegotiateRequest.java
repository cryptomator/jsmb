package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.negotiate.NegotiateContext;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * A SMB 2 NEGOTIATE Request
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5">SMB2 NEGOTIATE Request Specification</a>
 */
public record NegotiateRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public short structureSize() {
		return segment.get(Layouts.LE_INT16, 0); // should always be 36, regardless of dialects and negotiate contexts
	}

	public short dialectCount() {
		return segment.get(Layouts.LE_INT16, 2);
	}

	public short securityMode() {
		return segment.get(Layouts.LE_INT16, 4);
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

	public short negotiateContextCount() {
		return segment.get(Layouts.LE_INT16, 32);
	}

	public long clientStartTime() {
		return segment.get(Layouts.LE_INT64, 28);
	}

	public short[] dialects() {
		return segment.asSlice(36, dialectCount() * Short.BYTES).toArray(Layouts.LE_INT16);
	}

	public boolean supportsDialect(short dialect) {
		for (short d : dialects()) {
			if (d == dialect) {
				return true;
			}
		}
		return false;
	}

	public Set<NegotiateContext> negotiateContexts() {
		if (!supportsDialect(Dialects.SMB3_1_1)) {
			return Set.of();
		}

		// start of negotiate context is 8-byte-aligned
		int endOfDialects = 36 + dialectCount() * Short.BYTES;
		int padding = 8 - endOfDialects % 8;

		MemorySegment contextsSegment = segment.asSlice(endOfDialects + padding);
		Set<NegotiateContext> result = new HashSet<>();
		for (int offset = 0, i = 0; i < negotiateContextCount(); i++) {
			var ctx = NegotiateContext.parse(contextsSegment.asSlice(offset));
			result.add(ctx);
			var ctxSize = ctx.segmentSize();
			var paddingSize = (8 - ctxSize % 8) % 8;
			offset += ctxSize + paddingSize;
		}
		return result;
	}

	public <T extends NegotiateContext> T negotiateContext(Class<T> type) {
		return negotiateContexts().stream()
				.filter(type::isInstance)
				.map(type::cast)
				.findFirst()
				.orElse(null);
	}

}
