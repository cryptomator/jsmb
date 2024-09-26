package org.cryptomator.jsmb.smb1;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record SmbComNegotiateResponse(MemorySegment segment) implements SMB1Message {

	public static SmbComNegotiateResponse unsupportedDialectResponse() {
		var segment = MemorySegment.ofArray(new byte[32 + 1 + 2 + 2 + 1]); // header + word count + words + byte count + bytes
		segment.set(Layouts.LE_INT32, 0, PROTOCOL_ID); // Protocol ID
		segment.set(Layouts.BYTE, 4, (byte) 0x72); // Command
		segment.set(Layouts.LE_INT32, 5, NTStatus.STATUS_SUCCESS); // Status
		segment.set(Layouts.BYTE, 9, Flags1.REPLY); // Flags
		segment.set(Layouts.BYTE, 32, (byte) 0x01); // word count
		segment.set(Layouts.LE_UINT16, 33, (char) 0xFFFF); // Dialect index
		segment.set(Layouts.LE_UINT16, 35, (char) 0x0001); // Byte count
		segment.set(Layouts.BYTE, 36, (byte) 0x00); // bytes
		return new SmbComNegotiateResponse(segment);
	}
}
