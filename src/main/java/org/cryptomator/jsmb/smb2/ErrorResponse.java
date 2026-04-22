package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/41295064-be3f-41dc-9aa5-f68545f945f0">Sending an Error Response</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa">SMB2 ERROR Response</a>
 */
public record ErrorResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 9;

	private ErrorResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
		// ErrorData not supported yet, setting to 0
		errorContextCount((byte) 0);
		byteCount(0);
	}

	public void errorContextCount(byte errorContextCount) {
		segment.set(Layouts.BYTE, 2, errorContextCount);
	}

	public void byteCount(int byteCount) {
		segment.set(Layouts.LE_INT32, 4, byteCount);
	}

	public static ErrorResponse create(SMB2Message request, int errorCode) {
		PacketHeader header = PacketHeader.builder() //
				.command(request.header().command()) //
				.messageId(request.header().messageId()) //
				.sessionId(request.header().sessionId()) //
				.treeId(request.header().treeId()) //
				.status(errorCode) //
				.nextCommand(0) //
				.flags(Flags.SERVER_TO_REDIR)
				.creditResponse((char) 0) //
				.creditCharge((char) 0) //
				.build();
		return new ErrorResponse(header);
	}
}
