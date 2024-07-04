package org.cryptomator.jsmb.smb2;

import org.jetbrains.annotations.Range;

public enum Command {
	NEGOATIATE(0x0000),
	SESSION_SETUP(0x0001),
	LOGOFF(0x0002),
	TREE_CONNECT(0x0003),
	TREE_DISCONNECT(0x0004),
	CREATE(0x0005),
	CLOSE(0x0006),
	FLUSH(0x0007),
	READ(0x0008),
	WRITE(0x0009),
	LOCK(0x000A),
	IOCTL(0x000B),
	CANCEL(0x000C),
	ECHO(0x000D),
	QUERY_DIRECTORY(0x000E),
	CHANGE_NOTIFY(0x000F),
	QUERY_INFO(0x0010),
	SET_INFO(0x0011),
	OPLOCK_BREAK(0x0012);

	private final short value;

	Command(@Range(from = 0, to = 0xFFFF) int value) {
		assert value <= 0xFFFF;
		this.value = (short) value;
	}

	public short value() {
		return value;
	}

	/**
	 * Returns the enum constant of this type with the specified value.
	 * @param value numerical value of the command
	 * @throws IllegalArgumentException if this enum type has no constant with the specified nam
	 * @return the enum constant with the specified value
	 */
	public static Command valueOf(short value) {
		for (Command command : values()) {
			if (command.value == value) {
				return command;
			}
		}
		throw new IllegalArgumentException("Unknown command value: " + value);
	}
}
