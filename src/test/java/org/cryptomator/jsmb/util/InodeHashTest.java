package org.cryptomator.jsmb.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class InodeHashTest {

	@Test
	@DisplayName("of(\"\") returns the seed value — guards against accidentally changing the hash seed")
	void emptyStringReturnsSeed() {
		Assertions.assertEquals(1125899906842597L, InodeHash.of(""));
	}

	@Test
	@DisplayName("of() is deterministic — repeated calls with the same input yield the same value")
	void deterministic() {
		Assertions.assertEquals(InodeHash.of("sub/file.txt"), InodeHash.of("sub/file.txt"));
	}

	@Test
	@DisplayName("Different inputs produce different outputs for the paths we actually exercise")
	void distinguishesCommonInputs() {
		long a = InodeHash.of("file.txt");
		long b = InodeHash.of("sub/file.txt");
		long c = InodeHash.of("sub/other.txt");
		Assertions.assertNotEquals(a, b);
		Assertions.assertNotEquals(b, c);
		Assertions.assertNotEquals(a, c);
	}
}
