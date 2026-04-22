package org.cryptomator.jsmb.util;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public interface UInt16 {

	static IntStream stream(char[] array) {
		return IntStream.range(0, array.length).map(i -> array[i]);
	}

	static Set<Character> toSet(char[] array) {
		return IntStream.range(0, array.length)
				.mapToObj(i -> array[i])
				.collect(Collectors.toSet());
	}
}
