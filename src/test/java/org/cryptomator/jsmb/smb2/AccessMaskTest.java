package org.cryptomator.jsmb.smb2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AccessMaskTest {

	@Test
	@DisplayName("grantedFor() grants the specific rights asked for")
	void specificRights() {
		int desiredAccess = AccessMask.FILE_WRITE_DATA | AccessMask.FILE_READ_ATTRIBUTES | AccessMask.DELETE;

		Assertions.assertEquals(desiredAccess, AccessMask.grantedFor(desiredAccess));
	}

	@ParameterizedTest(name = "{0} → {1}")
	@DisplayName("grantedFor() replaces a generic right by the rights it stands for")
	@CsvSource({
			"0x80000000, 0x00120089", // GENERIC_READ
			"0x40000000, 0x00120116", // GENERIC_WRITE
			"0x20000000, 0x001200A1", // GENERIC_EXECUTE, plus the FILE_READ_DATA that FILE_EXECUTE brings along
			"0x10000000, 0x001F01FF", // GENERIC_ALL
			"0x02000000, 0x001F01FF", // MAXIMUM_ALLOWED
			"0xC0000000, 0x0012019F", // GENERIC_READ | GENERIC_WRITE
	})
	void genericRights(String desiredAccess, String expected) {
		int granted = AccessMask.grantedFor(Integer.parseUnsignedInt(desiredAccess.substring(2), 16));

		Assertions.assertEquals(Integer.parseUnsignedInt(expected.substring(2), 16), granted);
	}

	@Test
	@DisplayName("grantedFor() adds FILE_READ_DATA to FILE_EXECUTE")
	void executeImpliesRead() {
		int granted = AccessMask.grantedFor(AccessMask.FILE_EXECUTE);

		Assertions.assertEquals(AccessMask.FILE_EXECUTE | AccessMask.FILE_READ_DATA, granted);
	}

	@Test
	@DisplayName("grantedFor() keeps ACCESS_SYSTEM_SECURITY and drops reserved bits")
	void systemSecurityAndReservedBits() {
		int granted = AccessMask.grantedFor(AccessMask.FILE_READ_DATA | AccessMask.ACCESS_SYSTEM_SECURITY | 0x00000200);

		Assertions.assertEquals(AccessMask.FILE_READ_DATA | AccessMask.ACCESS_SYSTEM_SECURITY, granted);
	}
}
