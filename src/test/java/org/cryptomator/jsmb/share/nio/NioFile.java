package org.cryptomator.jsmb.share.nio;

import org.cryptomator.jsmb.share.SmbFile;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;

final class NioFile extends NioHandle implements SmbFile {

	private final FileChannel channel;

	NioFile(Path shareRoot, Path target, FileChannel channel, boolean existedBeforeOpen) {
		super(shareRoot, target, existedBeforeOpen);
		this.channel = channel;
	}

	@Override
	protected boolean isDirectory() {
		return false;
	}

	@Override
	public int read(ByteBuffer dst, long offset) throws IOException {
		return channel.read(dst, offset);
	}

	@Override
	public int write(ByteBuffer src, long offset) throws IOException {
		return channel.write(src, offset);
	}

	@Override
	public void flush() throws IOException {
		channel.force(true);
	}

	@Override
	public void setEndOfFile(long length) throws IOException {
		if (length < channel.size()) {
			channel.truncate(length);
		} else if (length > channel.size()) {
			// extend with zeros by writing a single byte at (length - 1)
			var pad = ByteBuffer.allocate(1);
			channel.write(pad, length - 1);
		}
	}

	@Override
	public void close() throws IOException {
		try {
			channel.close();
		} finally {
			if (deletePending) {
				Files.deleteIfExists(target);
			}
		}
	}
}
