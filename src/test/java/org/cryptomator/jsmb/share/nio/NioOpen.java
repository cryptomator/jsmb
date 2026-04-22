package org.cryptomator.jsmb.share.nio;

import org.cryptomator.jsmb.share.DirEntry;
import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.share.SmbOpen;
import org.cryptomator.jsmb.smb2.FileId;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Minimal {@link SmbOpen} implementation over {@link FileChannel} / NIO filesystem APIs.
 * Test-only: no locking, no retries, no fine-grained error mapping.
 */
class NioOpen implements SmbOpen {

	private final Path shareRoot;
	private Path target;
	private final FileChannel channel; // null iff directory
	private final boolean directory;
	private final FileId fileId = FileId.random();
	private boolean deletePending;

	NioOpen(Path shareRoot, Path target, FileChannel channel, boolean directory) {
		this.shareRoot = shareRoot;
		this.target = target;
		this.channel = channel;
		this.directory = directory;
	}

	@Override
	public FileId fileId() {
		return fileId;
	}

	@Override
	public FileBasicInfo queryBasic() throws IOException {
		var attrs = Files.readAttributes(target, BasicFileAttributes.class);
		int flags = directory ? FileBasicInfo.ATTR_DIRECTORY : FileBasicInfo.ATTR_NORMAL;
		return new FileBasicInfo(
				attrs.creationTime().toInstant(),
				attrs.lastAccessTime().toInstant(),
				attrs.lastModifiedTime().toInstant(),
				attrs.lastModifiedTime().toInstant(),
				flags);
	}

	@Override
	public FileStandardInfo queryStandard() throws IOException {
		var attrs = Files.readAttributes(target, BasicFileAttributes.class);
		long size = directory ? 0L : attrs.size();
		return new FileStandardInfo(size, size, 1, deletePending, directory);
	}

	@Override
	public void setBasic(FileBasicInfo info) throws IOException {
		var view = Files.getFileAttributeView(target, java.nio.file.attribute.BasicFileAttributeView.class);
		FileTime lastModified = info.lastWriteTime() != null ? FileTime.from(info.lastWriteTime()) : null;
		FileTime lastAccess = info.lastAccessTime() != null ? FileTime.from(info.lastAccessTime()) : null;
		FileTime creation = info.creationTime() != null ? FileTime.from(info.creationTime()) : null;
		view.setTimes(lastModified, lastAccess, creation);
	}

	@Override
	public void rename(String newPath, boolean replaceIfExists) throws IOException {
		var normalized = newPath.replace('\\', '/');
		while (normalized.startsWith("/")) normalized = normalized.substring(1);
		var destination = shareRoot.resolve(normalized);
		if (replaceIfExists) {
			Files.move(target, destination, StandardCopyOption.REPLACE_EXISTING);
		} else {
			Files.move(target, destination);
		}
		target = destination;
	}

	@Override
	public void markForDeletion() {
		deletePending = true;
	}

	@Override
	public int read(ByteBuffer dst, long offset) throws IOException {
		requireFile();
		return channel.read(dst, offset);
	}

	@Override
	public int write(ByteBuffer src, long offset) throws IOException {
		requireFile();
		return channel.write(src, offset);
	}

	@Override
	public void flush() throws IOException {
		requireFile();
		channel.force(true);
	}

	@Override
	public void setEndOfFile(long length) throws IOException {
		requireFile();
		if (length < channel.size()) {
			channel.truncate(length);
		} else if (length > channel.size()) {
			// extend with zeros by writing a single byte at (length - 1)
			var pad = ByteBuffer.allocate(1);
			channel.write(pad, length - 1);
		}
	}

	@Override
	public Stream<DirEntry> listChildren(String pattern) throws IOException {
		if (!directory) throw new UnsupportedOperationException("Not a directory");
		var glob = (pattern == null || pattern.isEmpty()) ? "*" : pattern;
		DirectoryStream<Path> stream = Files.newDirectoryStream(target, glob);
		return StreamSupport.stream(stream.spliterator(), false)
				.map(NioOpen::toDirEntry)
				.onClose(() -> {
					try {
						stream.close();
					} catch (IOException e) {
						throw new java.io.UncheckedIOException(e);
					}
				});
	}

	@Override
	public void close() throws IOException {
		try {
			if (channel != null) {
				channel.close();
			}
		} finally {
			if (deletePending) {
				Files.deleteIfExists(target);
			}
		}
	}

	private void requireFile() {
		if (directory) throw new UnsupportedOperationException("Operation not valid on a directory");
	}

	private static DirEntry toDirEntry(Path entry) {
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
			return new DirEntry(entry.getFileName().toString(), basic, standard);
		} catch (IOException e) {
			throw new java.io.UncheckedIOException(e);
		}
	}
}
