package org.cryptomator.jsmb.smb1;

import org.cryptomator.jsmb.common.SMBMessage;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

/**
 * A SMB 1 Message
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/4d330f4c-151c-4d79-b207-40bd4f754da9">SMB1 Message Structure</a>
 */
public sealed interface SMB1Message extends SMBMessage permits SmbComNegotiateRequest, SmbComNegotiateResponse {

	int PROTOCOL_ID = 0x424D53FF; // 0xFF S M B

	interface Flags1 {
		byte LOCK_AND_READ_OK = 0x01;
		byte BUF_AVAIL = 0x02;
		byte CASE_INSENSITIVE = 0x08;
		byte CANONICALIZED_PATHS = 0x10;
		byte OPLOCK = 0x20;
		byte OPBATCH = 0x40;
		byte REPLY = (byte) 0x80;
	}

	interface Flags2 {
		char LONG_NAMES = 0x0001;
		char EAS = 0x0002;
		char SMB_SECURITY_SIGNATURE = 0x0004;
		char IS_LONG_NAME = 0x0040;
		char DFS = 0x1000;
		char PAGING_IO = 0x2000;
		char NT_STATUS = 0x4000;
		char UNICODE = 0x8000;
	}

	MemorySegment segment();

	default byte[] serialize() {
		var buf = segment().asByteBuffer();
		var result = new byte[buf.remaining()];
		buf.get(0, result);
		return result;
	}

	default byte command() {
		return segment().get(Layouts.BYTE, 4);
	}

	default int status() {
		return segment().get(Layouts.LE_INT32, 5);
	}

	default byte flags() {
		return segment().get(Layouts.BYTE, 9);
	}

	default char flags2() {
		return segment().get(Layouts.LE_UINT16, 10);
	}

	default char pidHigh() {
		return segment().get(Layouts.LE_UINT16, 12);
	}

	default long securityFeatures() {
		return segment().get(Layouts.LE_INT32, 14);
	}

	default char tid() {
		return segment().get(Layouts.LE_UINT16, 24);
	}

	default char pidLow() {
		return segment().get(Layouts.LE_UINT16, 26);
	}

	default char uid() {
		return segment().get(Layouts.LE_UINT16, 28);
	}

	default char mid() {
		return segment().get(Layouts.LE_UINT16, 30);
	}

	default byte wordCount() {
		return segment().get(Layouts.BYTE, 32);
	}

	default MemorySegment words() {
		return segment().asSlice(33, wordCount() * Character.BYTES);
	}

	default char byteCount() {
		return segment().get(Layouts.LE_UINT16, 33 + wordCount() * Character.BYTES);
	}

	default MemorySegment bytes() {
		return segment().asSlice(35 + wordCount() * Character.BYTES, byteCount());
	}

}
