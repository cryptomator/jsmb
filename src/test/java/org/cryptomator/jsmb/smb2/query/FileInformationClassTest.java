package org.cryptomator.jsmb.smb2.query;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FileInformationClassTest {

	@Test
	@DisplayName("Wire values match MS-FSCC section numbers")
	void wireValues() {
		Assertions.assertEquals(1, FileInformationClass.FILE_DIRECTORY_INFORMATION.value());
		Assertions.assertEquals(2, FileInformationClass.FILE_FULL_DIRECTORY_INFORMATION.value());
		Assertions.assertEquals(3, FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION.value());
		Assertions.assertEquals(12, FileInformationClass.FILE_NAMES_INFORMATION.value());
		Assertions.assertEquals(37, FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION.value());
		Assertions.assertEquals(38, FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION.value());
	}

	@Test
	@DisplayName("fromValue resolves every defined wire value")
	void fromValueResolvesKnown() {
		for (var v : FileInformationClass.values()) {
			Assertions.assertSame(v, FileInformationClass.fromValue(v.value()));
		}
	}

	@Test
	@DisplayName("fromValue rejects an unknown class with IllegalArgumentException")
	void fromValueRejectsUnknown() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> FileInformationClass.fromValue(99));
	}
}
