package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.SMBMessage;
import org.cryptomator.jsmb.smb2.crypto.MessageSigner;
import org.cryptomator.jsmb.util.Bytes;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.Range;

import java.lang.foreign.MemorySegment;
import java.util.Objects;

/**
 * A SMB 2 Message
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4">SMB2 Packet Header Specification</a>
 */
public interface SMB2Message extends SMBMessage {

	int PROTOCOL_ID = 0x424D53FE; // 0xFE S M B

	interface Flags {
		int SERVER_TO_REDIR = 0x00000001;
		int ASYNC_COMMAND = 0x00000002;
		int RELATED_OPERATIONS = 0x00000004;
		int SIGNED = 0x00000008;
		int PRIORITY_MASK = 0x00000070;
		int DFS_OPERATIONS = 0x10000000;
		int REPLAY_OPERATION = 0x20000000;

		@Range(from = 0, to = 7)
		static int priorityFrom(int flags) {
			return (flags & PRIORITY_MASK) >>> 4;
		}

		static int withPriority(int flags, @Range(from = 0, to = 7) int priority) {
			return (flags & ~PRIORITY_MASK) | (priority << 4);
		}
	}

	PacketHeader header();

	MemorySegment segment();

	default byte[] serialize() {
		return Bytes.concat(header().segment().toArray(Layouts.BYTE), segment().toArray(Layouts.BYTE));
	}

	/**
	 * Tells whether a request conforms to its structure definition, as far as that is needed to read it safely.
	 *
	 * @return {@code false} if the StructureSize is wrong, the message is shorter than the structure's fixed part, or a variable-length field isn't located within the message
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/853e5234-d5d6-4a18-a2f5-1c792e562947">Handling Incorrectly Formatted Requests</a>
	 */
	default boolean isWellFormed() {
		return true;
	}

	/**
	 * Checks the fixed part of a message body.
	 *
	 * @param body          the message body, i.e. everything following the SMB2 header
	 * @param structureSize the StructureSize the structure definition calls for. An odd value includes the first byte of the variable part, which doesn't count towards the fixed part.
	 * @return {@code true} if the body is long enough for the fixed part and declares the given StructureSize
	 */
	static boolean hasStructure(MemorySegment body, int structureSize) {
		int fixedSize = structureSize & ~1;
		return body.byteSize() >= fixedSize && body.get(Layouts.LE_UINT16, 0) == structureSize;
	}

	/**
	 * Checks the location of a variable-length field.
	 *
	 * @param body   the message body, i.e. everything following the SMB2 header
	 * @param offset the field's offset from the beginning of the SMB2 header, as found in the message
	 * @param length the field's length in bytes, as found in the message
	 * @return {@code true} if the field is empty or lies within the body
	 */
	static boolean containsBuffer(MemorySegment body, long offset, long length) {
		if (length == 0) {
			return true; // clients are free to put anything into the offset of an empty field
		}
		long start = offset - PacketHeader.STRUCTURE_SIZE;
		return start >= 0 && length > 0 && start + length <= body.byteSize();
	}

	/**
	 * Puts the credit fields into the header of a response.
	 *
	 * @param creditCharge   the CreditCharge of the request this message responds to
	 * @param creditResponse the number of credits granted to the client
	 * @return this message if its header says so already, otherwise a copy with an accordingly changed header
	 */
	default SMB2Message withCredits(char creditCharge, char creditResponse) {
		if (header().creditCharge() == creditCharge && header().creditResponse() == creditResponse) {
			return this;
		}
		record CreditedMessage(PacketHeader header, MemorySegment segment) implements SMB2Message {}
		return new CreditedMessage(header().copy().creditCharge(creditCharge).creditResponse(creditResponse).build(), segment());
	}

	default SMB2Message sign(byte[] key, Connection connection) {
		assert Objects.equals(connection.dialect, "3.1.1");
		record SignedMessage(PacketHeader header, MemorySegment segment) implements SMB2Message {}
		return new SignedMessage(new MessageSigner().sign(this, key, connection), segment());
	}

}
