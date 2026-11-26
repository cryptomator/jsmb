package org.cryptomator.jsmb.smb2;

import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Checks and converts the path names clients send, which are relative to the share root and delimited by backslashes.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ffb795f3-027d-4a3c-997d-3085f2332f6f">MS-FSCC 2.1.5 Pathname</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/2917da5c-253c-4c0e-aaf6-9dddc37d2e6e">MS-FSCC 2.1.5.2 Filename</a>
 */
public final class PathNames {

	private static final Pattern SEPARATOR = Pattern.compile("\\\\");
	private static final int MAX_PATH_LENGTH = 32_760;
	private static final int MAX_COMPONENT_LENGTH = 255;
	private static final String ILLEGAL_CHARACTERS = "\"/:|<>*?"; // besides the backslash, which separates components, and control characters

	private PathNames() {
	}

	/**
	 * Tells whether a path name is one that may be handed to a share backend.
	 * <p>
	 * That takes components free of characters that are illegal in a file name, and none of them being {@code .} or {@code ..},
	 * which must not be sent over the wire (MS-FSCC 2.1.5.1). Named streams aren't supported, so the colon that introduces one is illegal as well.
	 * Leading, trailing and repeated separators are fine, as {@link #toBackendPath(String)} strips them.
	 *
	 * @param pathName a path name as sent by the client
	 * @return {@code true} if the path name is valid
	 */
	public static boolean isValid(String pathName) {
		if (pathName.length() > MAX_PATH_LENGTH) {
			return false;
		}
		for (var component : SEPARATOR.split(pathName)) {
			if (component.length() > MAX_COMPONENT_LENGTH || component.equals(".") || component.equals("..")) {
				return false;
			}
			if (component.chars().anyMatch(c -> c < 0x20 || ILLEGAL_CHARACTERS.indexOf(c) >= 0)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Tells whether a path name refers to a named stream of a file, as in {@code file.txt:stream:$DATA}.
	 *
	 * @param pathName a path name as sent by the client
	 * @return {@code true} if a component of the path name has a stream name or stream type
	 */
	public static boolean referencesStream(String pathName) {
		return pathName.indexOf(':') >= 0;
	}

	/**
	 * Tells whether a path name ends with a separator, by which a client says that it means a directory.
	 *
	 * @param pathName a path name as sent by the client
	 * @return {@code true} if the last character is a backslash
	 */
	public static boolean hasTrailingSeparator(String pathName) {
		return pathName.endsWith("\\");
	}

	/**
	 * Converts a path name into the form share backends and {@code Open.path} use.
	 *
	 * @param pathName a valid path name as sent by the client
	 * @return the path delimited by forward slashes, without leading, trailing or repeated separators; empty for the share root
	 */
	public static String toBackendPath(String pathName) {
		return Arrays.stream(SEPARATOR.split(pathName)).filter(component -> !component.isEmpty()).collect(Collectors.joining("/"));
	}
}
