package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.MalformedMessageException;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.foreign.MemorySegment;

class SMB2MessageParserTest {

	@Test
	@DisplayName("A command code that the protocol doesn't define is rejected as malformed")
	void unknownCommand() {
		var message = message((char) 0x0013);

		Assertions.assertThrows(MalformedMessageException.class, () -> SMB2MessageParser.parse(message));
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("A valid command that isn't implemented is parsed as UnhandledRequest")
	@EnumSource(value = Command.class, names = {"LOCK", "OPLOCK_BREAK"})
	void unimplementedCommand(Command command) {
		var message = message(command.value());

		var request = SMB2MessageParser.parse(message);

		Assertions.assertInstanceOf(UnhandledRequest.class, request);
		Assertions.assertEquals(command.value(), request.header().command());
	}

	// an SMB2 header followed by a body that consists of nothing but its StructureSize field
	private static MemorySegment message(char command) {
		var header = PacketHeader.builder().command(command).build();
		var message = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE + 2]);
		MemorySegment.copy(header.segment(), 0, message, 0, PacketHeader.STRUCTURE_SIZE);
		message.set(Layouts.LE_UINT16, PacketHeader.STRUCTURE_SIZE, (char) 2);
		return message;
	}
}
