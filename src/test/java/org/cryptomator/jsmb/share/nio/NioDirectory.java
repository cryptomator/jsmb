package org.cryptomator.jsmb.share.nio;

import org.cryptomator.jsmb.share.DirEntry;
import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.share.SmbDirectory;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

final class NioDirectory extends NioHandle implements SmbDirectory {

	NioDirectory(Path shareRoot, Path target, boolean existedBeforeOpen) {
		super(shareRoot, target, existedBeforeOpen);
	}

	@Override
	protected boolean isDirectory() {
		return true;
	}

	@Override
	public Stream<DirEntry> listChildren(String pattern) throws IOException {
		var glob = (pattern == null || pattern.isEmpty()) ? "*" : pattern;
		DirectoryStream<Path> stream = Files.newDirectoryStream(target, glob);
		var realChildren = StreamSupport.stream(stream.spliterator(), false)
				.map(NioDirectory::toDirEntry)
				.onClose(() -> {
					try {
						stream.close();
					} catch (IOException e) {
						throw new java.io.UncheckedIOException(e);
					}
				});

		// Synthetic "." / ".." entries. Reuse this directory's own metadata for both — clients don't
		// rely on the pseudo-entries carrying the parent's exact attributes. ".." only when we're
		// below the share root; at the share root SMB clients don't expect it (there's no "above").
		var self = toDirEntry(target, ".");
		Stream<DirEntry> pseudoEntries;
		if (target.equals(shareRoot)) {
			pseudoEntries = smbWildcardMatches(glob, ".") ? Stream.of(self) : Stream.empty();
		} else {
			var parent = toDirEntry(target, "..");
			pseudoEntries = Stream.of(self, parent).filter(e -> smbWildcardMatches(glob, e.name()));
		}

		return Stream.concat(pseudoEntries, realChildren);
	}

	@Override
	public void close() throws IOException {
		if (deletePending) {
			Files.deleteIfExists(target);
		}
	}

	/**
	 * Minimal SMB wildcard matcher ({@code *}, {@code ?}). Deliberately ignores the DOS quirk characters
	 * ({@code <}, {@code >}, {@code "}); clients we integration-test against don't use them.
	 */
	private static boolean smbWildcardMatches(String pattern, String name) {
		if (pattern == null || pattern.isEmpty() || pattern.equals("*")) return true;
		return wildcardMatch(pattern, 0, name, 0);
	}

	private static boolean wildcardMatch(String p, int pi, String n, int ni) {
		while (pi < p.length()) {
			char pc = p.charAt(pi);
			if (pc == '*') {
				if (pi + 1 == p.length()) return true;
				for (int i = ni; i <= n.length(); i++) {
					if (wildcardMatch(p, pi + 1, n, i)) return true;
				}
				return false;
			}
			if (ni >= n.length()) return false;
			if (pc != '?' && pc != n.charAt(ni)) return false;
			pi++;
			ni++;
		}
		return ni == n.length();
	}

	private static DirEntry toDirEntry(Path entry) {
		return toDirEntry(entry, entry.getFileName().toString());
	}

	/** Overload that lets the caller override the name — used by the synthetic {@code "."} / {@code ".."} entries. */
	private static DirEntry toDirEntry(Path entry, String name) {
		try {
			var attrs = Files.readAttributes(entry, BasicFileAttributes.class);
			boolean isDir = attrs.isDirectory();
			int flags = isDir ? FileBasicInfo.ATTR_DIRECTORY : FileBasicInfo.ATTR_NORMAL;
			var basic = new FileBasicInfo(
					attrs.creationTime().toInstant(),
					attrs.lastAccessTime().toInstant(),
					attrs.lastModifiedTime().toInstant(),
					attrs.lastModifiedTime().toInstant(),
					flags);
			long size = isDir ? 0L : attrs.size();
			var standard = new FileStandardInfo(size, size, 1, false, isDir);
			return new DirEntry(name, basic, standard);
		} catch (IOException e) {
			throw new java.io.UncheckedIOException(e);
		}
	}
}
