package org.cryptomator.jsmb.share.nio;

import org.cryptomator.jsmb.share.FsAttributes;
import org.cryptomator.jsmb.share.FsSize;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.SmbOpen;
import org.cryptomator.jsmb.share.SmbShare;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;
import java.util.Set;

/**
 * Minimal, happy-path {@link SmbShare} implementation rooted at a {@link Path}. Test-only: no
 * production-grade error mapping, concurrency protection, ACL handling, symlink resolution, or
 * path-traversal guards. Exists solely to drive the SPI from integration tests.
 */
public class NioShare implements SmbShare {

	private final Path root;
	private final String fileSystemName;

	public NioShare(Path root) {
		this(root, "NTFS");
	}

	public NioShare(Path root, String fileSystemName) {
		this.root = root;
		this.fileSystemName = fileSystemName;
	}

	Path root() {
		return root;
	}

	@Override
	public SmbOpen open(String path, OpenParams params) throws IOException {
		var target = resolve(path);
		var wantDir = (params.createOptions() & OpenParams.OPTION_DIRECTORY_FILE) != 0;
		var exists = Files.exists(target);

		switch (params.disposition()) {
			case OPEN -> {
				if (!exists) throw new NoSuchFileException(path);
			}
			case CREATE -> {
				if (exists) throw new FileAlreadyExistsException(path);
				createTarget(target, wantDir);
			}
			case OPEN_IF -> {
				if (!exists) createTarget(target, wantDir);
			}
			case SUPERSEDE, OVERWRITE_IF -> {
				if (exists) {
					Files.delete(target);
				}
				createTarget(target, wantDir);
			}
			case OVERWRITE -> {
				if (!exists) throw new NoSuchFileException(path);
				Files.delete(target);
				createTarget(target, wantDir);
			}
		}

		var isDir = Files.isDirectory(target);
		FileChannel channel = null;
		if (!isDir) {
			Set<StandardOpenOption> opts = EnumSet.of(StandardOpenOption.READ, StandardOpenOption.WRITE);
			channel = FileChannel.open(target, opts);
		}
		return new NioOpen(root, target, channel, isDir, exists);
	}

	@Override
	public FsAttributes fsAttributes() {
		int flags = FsAttributes.FS_ATTR_CASE_SENSITIVE_SEARCH
				| FsAttributes.FS_ATTR_CASE_PRESERVED_NAMES
				| FsAttributes.FS_ATTR_UNICODE_ON_DISK;
		return new FsAttributes(flags, 255, fileSystemName);
	}

	@Override
	public FsSize fsSize() throws IOException {
		var store = Files.getFileStore(root);
		long total = store.getTotalSpace();
		long avail = store.getUsableSpace();
		int bytesPerSector = 4096;
		int sectorsPerUnit = 1;
		long unitBytes = (long) bytesPerSector * sectorsPerUnit;
		return new FsSize(total / unitBytes, avail / unitBytes, sectorsPerUnit, bytesPerSector);
	}

	private Path resolve(String path) {
		var normalized = path.replace('\\', '/');
		while (normalized.startsWith("/")) normalized = normalized.substring(1);
		return normalized.isEmpty() ? root : root.resolve(normalized);
	}

	private static void createTarget(Path target, boolean asDirectory) throws IOException {
		if (asDirectory) {
			Files.createDirectory(target);
		} else {
			Files.createFile(target);
		}
	}
}
