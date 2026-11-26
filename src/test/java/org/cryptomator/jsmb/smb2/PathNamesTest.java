package org.cryptomator.jsmb.smb2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class PathNamesTest {

	@ParameterizedTest(name = "\"{0}\"")
	@DisplayName("isValid() accepts path names of legal components, whatever separators surround them")
	@ValueSource(strings = {"", "file.txt", "dir\\file.txt", "\\dir\\file.txt", "dir\\", "dir\\\\file.txt", "...", ".hidden", "a b", "ümlaut.txt"})
	void validNames(String pathName) {
		Assertions.assertTrue(PathNames.isValid(pathName));
	}

	@ParameterizedTest(name = "\"{0}\"")
	@DisplayName("isValid() rejects dot directory names and characters that are illegal in a file name")
	@ValueSource(strings = {".", "..", "dir\\..\\file.txt", "dir\\.", "..\\outside.txt", "a/b", "a:b", "a|b", "a<b", "a>b", "a*b", "a?b", "a\"b", "a\tb", "a\0b"})
	void invalidNames(String pathName) {
		Assertions.assertFalse(PathNames.isValid(pathName));
	}

	@Test
	@DisplayName("isValid() rejects a component of more than 255 characters")
	void longComponent() {
		var fits = "dir\\" + "x".repeat(255);
		var tooLong = "dir\\" + "x".repeat(256);

		Assertions.assertTrue(PathNames.isValid(fits));
		Assertions.assertFalse(PathNames.isValid(tooLong));
	}

	@Test
	@DisplayName("isValid() rejects a path name of more than 32760 characters")
	void longPath() {
		var tooLong = "dir\\".repeat(8191); // 32764 characters

		Assertions.assertFalse(PathNames.isValid(tooLong));
	}

	@ParameterizedTest(name = "\"{0}\" → {1}")
	@DisplayName("referencesStream() spots a stream name or stream type")
	@CsvSource({"file.txt:stream, true", "file.txt:stream:$DATA, true", "file.txt::$DATA, true", "dir\\file.txt, false"})
	void streams(String pathName, boolean expected) {
		Assertions.assertEquals(expected, PathNames.referencesStream(pathName));
	}

	@ParameterizedTest(name = "\"{0}\" → \"{1}\"")
	@DisplayName("toBackendPath() delimits by forward slashes and strips leading, trailing and repeated separators")
	@CsvSource({"file.txt, file.txt", "dir\\sub\\file.txt, dir/sub/file.txt", "\\dir\\file.txt, dir/file.txt", "dir\\, dir", "dir\\\\file.txt, dir/file.txt", "'', ''", "\\, ''"})
	void backendPath(String pathName, String expected) {
		Assertions.assertEquals(expected, PathNames.toBackendPath(pathName));
	}
}
