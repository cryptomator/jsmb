package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.lang.foreign.MemorySegment;

class SMB2MessageTest {

	@Nested
	@DisplayName("isWellFormed() of requests: fixed part")
	class FixedPart {

		// command, StructureSize as defined in MS-SMB2 2.2
		private static final String REQUESTS = """
				NEGOTIATE, 36
				SESSION_SETUP, 25
				LOGOFF, 4
				TREE_CONNECT, 9
				TREE_DISCONNECT, 4
				CREATE, 57
				CLOSE, 24
				FLUSH, 24
				READ, 49
				WRITE, 49
				IOCTL, 57
				CANCEL, 4
				ECHO, 4
				QUERY_DIRECTORY, 33
				CHANGE_NOTIFY, 32
				QUERY_INFO, 41
				SET_INFO, 33
				""";

		@ParameterizedTest(name = "{0}")
		@DisplayName("A request consisting of its fixed part with the right StructureSize is well-formed")
		@CsvSource(textBlock = REQUESTS)
		void minimalRequest(Command command, int structureSize) {
			var request = request(command, body(fixedSize(structureSize), structureSize));

			Assertions.assertTrue(request.isWellFormed());
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("A request with a wrong StructureSize is malformed")
		@CsvSource(textBlock = REQUESTS)
		void wrongStructureSize(Command command, int structureSize) {
			var request = request(command, body(fixedSize(structureSize), structureSize + 2));

			Assertions.assertFalse(request.isWellFormed());
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("A request that is shorter than its fixed part is malformed")
		@CsvSource(textBlock = REQUESTS)
		void truncatedRequest(Command command, int structureSize) {
			var request = request(command, body(fixedSize(structureSize) - 2, structureSize));

			Assertions.assertFalse(request.isWellFormed());
		}
	}

	@Nested
	@DisplayName("isWellFormed() of requests: variable-length fields")
	class VariablePart {

		// command, StructureSize, position and width of the offset field, position and width of the length field (positions within the body, widths in bytes)
		private static final String BUFFERS = """
				SESSION_SETUP,   25, 12, 2, 14, 2
				TREE_CONNECT,     9,  4, 2,  6, 2
				CREATE,          57, 44, 2, 46, 2
				CREATE,          57, 48, 4, 52, 4
				WRITE,           49,  2, 2,  4, 4
				IOCTL,           57, 24, 4, 28, 4
				QUERY_DIRECTORY, 33, 24, 2, 26, 2
				QUERY_INFO,      41,  8, 2, 12, 4
				SET_INFO,        33,  8, 2,  4, 4
				""";

		private static final int BUFFER_SIZE = 8;

		@ParameterizedTest(name = "{0}, offset at {2}")
		@DisplayName("A buffer that ends with the message is well-formed")
		@CsvSource(textBlock = BUFFERS)
		void bufferWithinMessage(Command command, int structureSize, int offsetPos, int offsetWidth, int lengthPos, int lengthWidth) {
			var body = body(fixedSize(structureSize) + BUFFER_SIZE, structureSize);
			set(body, offsetPos, offsetWidth, PacketHeader.STRUCTURE_SIZE + fixedSize(structureSize));
			set(body, lengthPos, lengthWidth, BUFFER_SIZE);

			Assertions.assertTrue(request(command, body).isWellFormed());
		}

		@ParameterizedTest(name = "{0}, offset at {2}")
		@DisplayName("A buffer that reaches beyond the end of the message is malformed")
		@CsvSource(textBlock = BUFFERS)
		void bufferBeyondMessage(Command command, int structureSize, int offsetPos, int offsetWidth, int lengthPos, int lengthWidth) {
			var body = body(fixedSize(structureSize) + BUFFER_SIZE, structureSize);
			set(body, offsetPos, offsetWidth, PacketHeader.STRUCTURE_SIZE + fixedSize(structureSize));
			set(body, lengthPos, lengthWidth, BUFFER_SIZE + 1);

			Assertions.assertFalse(request(command, body).isWellFormed());
		}

		@ParameterizedTest(name = "{0}, offset at {2}")
		@DisplayName("A buffer that starts within the SMB2 header is malformed")
		@CsvSource(textBlock = BUFFERS)
		void bufferWithinHeader(Command command, int structureSize, int offsetPos, int offsetWidth, int lengthPos, int lengthWidth) {
			var body = body(fixedSize(structureSize) + BUFFER_SIZE, structureSize);
			set(body, offsetPos, offsetWidth, PacketHeader.STRUCTURE_SIZE - 1);
			set(body, lengthPos, lengthWidth, BUFFER_SIZE);

			Assertions.assertFalse(request(command, body).isWellFormed());
		}

		@ParameterizedTest(name = "{0}, offset at {2}")
		@DisplayName("An empty buffer is well-formed, whatever its offset")
		@CsvSource(textBlock = BUFFERS)
		void emptyBuffer(Command command, int structureSize, int offsetPos, int offsetWidth, int lengthPos, int lengthWidth) {
			var body = body(fixedSize(structureSize), structureSize);
			set(body, offsetPos, offsetWidth, 0xFFFF);
			set(body, lengthPos, lengthWidth, 0);

			Assertions.assertTrue(request(command, body).isWellFormed());
		}

		@Test
		@DisplayName("A NEGOTIATE request whose dialects don't fit into the message is malformed")
		void dialectsBeyondMessage() {
			var body = body(36 + 2, 36); // room for one dialect
			body.set(Layouts.LE_UINT16, 2, (char) 2); // DialectCount

			Assertions.assertFalse(request(Command.NEGOTIATE, body).isWellFormed());
		}

		@Test
		@DisplayName("A NEGOTIATE request whose dialects fit into the message is well-formed")
		void dialectsWithinMessage() {
			var body = body(36 + 4, 36);
			body.set(Layouts.LE_UINT16, 2, (char) 2); // DialectCount

			Assertions.assertTrue(request(Command.NEGOTIATE, body).isWellFormed());
		}

		private static void set(MemorySegment body, int position, int width, int value) {
			if (width == 2) {
				body.set(Layouts.LE_UINT16, position, (char) value);
			} else {
				body.set(Layouts.LE_INT32, position, value);
			}
		}
	}

	// an odd StructureSize includes the first byte of the variable part
	private static int fixedSize(int structureSize) {
		return structureSize & ~1;
	}

	private static MemorySegment body(int size, int structureSize) {
		var body = MemorySegment.ofArray(new byte[size]);
		body.set(Layouts.LE_UINT16, 0, (char) structureSize);
		return body;
	}

	// goes through the parser, so that each command gets tested with the request type that is used for it in production
	private static SMB2Message request(Command command, MemorySegment body) {
		var header = PacketHeader.builder().command(command.value()).build();
		var message = MemorySegment.ofArray(new byte[(int) (PacketHeader.STRUCTURE_SIZE + body.byteSize())]);
		MemorySegment.copy(header.segment(), 0, message, 0, PacketHeader.STRUCTURE_SIZE);
		MemorySegment.copy(body, 0, message, PacketHeader.STRUCTURE_SIZE, body.byteSize());
		return SMB2MessageParser.parse(message);
	}
}
