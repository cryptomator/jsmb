package org.cryptomator.jsmb.share.nio;

import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.share.SmbDirectory;
import org.cryptomator.jsmb.share.SmbFile;
import org.cryptomator.jsmb.share.SmbOpen;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

/**
 * Shared NIO state + common {@link SmbOpen} behaviour for {@link NioFile} and {@link NioDirectory}. Test-only:
 * no locking, no retries, no fine-grained error mapping.
 *
 * <p>This class does not itself implement {@link SmbOpen} — the sealed interface only permits {@link SmbFile} and
 * {@link SmbDirectory}. The concrete subclasses carry the interface declaration; the methods here are plain
 * inheritable definitions that satisfy those contracts through subclass inheritance.
 */
abstract class NioHandle {

	protected final Path shareRoot;
	protected Path target;
	protected final boolean existedBeforeOpen;
	protected final FileId fileId = FileId.random();
	protected boolean deletePending;

	NioHandle(Path shareRoot, Path target, boolean existedBeforeOpen) {
		this.shareRoot = shareRoot;
		this.target = target;
		this.existedBeforeOpen = existedBeforeOpen;
	}

	public FileId fileId() {
		return fileId;
	}

	public boolean existedBeforeOpen() {
		return existedBeforeOpen;
	}

	public void markForDeletion() {
		deletePending = true;
	}

	public FileBasicInfo queryBasic() throws IOException {
		var attrs = Files.readAttributes(target, BasicFileAttributes.class);
		int flags = isDirectory() ? FileBasicInfo.ATTR_DIRECTORY : FileBasicInfo.ATTR_NORMAL;
		return new FileBasicInfo(
				attrs.creationTime().toInstant(),
				attrs.lastAccessTime().toInstant(),
				attrs.lastModifiedTime().toInstant(),
				attrs.lastModifiedTime().toInstant(),
				flags);
	}

	public FileStandardInfo queryStandard() throws IOException {
		var attrs = Files.readAttributes(target, BasicFileAttributes.class);
		boolean dir = isDirectory();
		long size = dir ? 0L : attrs.size();
		return new FileStandardInfo(size, size, 1, deletePending, dir);
	}

	public void setBasic(FileBasicInfo info) throws IOException {
		var view = Files.getFileAttributeView(target, java.nio.file.attribute.BasicFileAttributeView.class);
		FileTime lastModified = info.lastWriteTime() != null ? FileTime.from(info.lastWriteTime()) : null;
		FileTime lastAccess = info.lastAccessTime() != null ? FileTime.from(info.lastAccessTime()) : null;
		FileTime creation = info.creationTime() != null ? FileTime.from(info.creationTime()) : null;
		view.setTimes(lastModified, lastAccess, creation);
	}

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

	protected abstract boolean isDirectory();
}
