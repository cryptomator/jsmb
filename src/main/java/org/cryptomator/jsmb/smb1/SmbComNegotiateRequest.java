package org.cryptomator.jsmb.smb1;

import org.cryptomator.jsmb.util.Layouts;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public record SmbComNegotiateRequest(MemorySegment segment) implements SMB1Message {

	public static final int COMMAND = 0x72;

	// see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/25c8c3c9-58fc-4bb8-aa8f-0272dede84c5 on how to parse this
	public List<String> dialects() {
		// Charset charset = (header.flags2() & SMB1Header.Flags2.UNICODE) == SMB1Header.Flags2.UNICODE ? StandardCharsets.UTF_16LE : StandardCharsets.US_ASCII;
		var bos = new ByteArrayOutputStream();
		List<String> dialects = new ArrayList<>();
		var bytes = bytes();
		for (int i = 0; i < byteCount(); i++) {
			byte b = bytes.get(Layouts.BYTE, i);
			switch (b) {
				case 0x02 -> bos = new ByteArrayOutputStream();
				default -> bos.write(bytes.get(Layouts.BYTE, i));
				case 0x00 -> dialects.add(bos.toString(StandardCharsets.US_ASCII));
			}
		}
		return dialects;
	}
}
