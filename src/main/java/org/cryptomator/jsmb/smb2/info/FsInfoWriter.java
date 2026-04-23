package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FsAttributes;
import org.cryptomator.jsmb.share.FsSize;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Serializes the MS-FSCC 2.5 filesystem-level info classes that {@code QUERY_INFO} can return for
 * an open on a share.
 */
public final class FsInfoWriter {

	/** Disk filesystem — {@code FILE_DEVICE_DISK}. */
	private static final int DEVICE_TYPE_DISK = 0x07;
	/** {@code FILE_REMOTE_DEVICE} — the share is a network filesystem. */
	private static final int DEVICE_CHARACTERISTICS_REMOTE = 0x10;

	private FsInfoWriter() {}

	public static byte[] write(FsInfoClass cls, FsSize size, FsAttributes attrs, String volumeLabel, long volumeCreationFileTime) {
		return switch (cls) {
			case FILE_FS_VOLUME_INFORMATION -> volumeInfo(volumeLabel, volumeCreationFileTime);
			case FILE_FS_SIZE_INFORMATION -> sizeInfo(size);
			case FILE_FS_DEVICE_INFORMATION -> deviceInfo();
			case FILE_FS_ATTRIBUTE_INFORMATION -> attributeInfo(attrs);
			case FILE_FS_FULL_SIZE_INFORMATION -> fullSizeInfo(size);
		};
	}

	/**
	 * MS-FSCC 2.5.9 — {@code VolumeCreationTime(8) + VolumeSerialNumber(4) + VolumeLabelLength(4) +
	 * SupportsObjects(1) + Reserved(1) + VolumeLabel(UTF-16LE, variable)}.
	 */
	static byte[] volumeInfo(String label, long creationFileTime) {
		byte[] labelBytes = label.getBytes(StandardCharsets.UTF_16LE);
		var buf = alloc(18 + labelBytes.length);
		buf.putLong(creationFileTime);                 // VolumeCreationTime
		buf.putInt(volumeSerial(label));               // VolumeSerialNumber
		buf.putInt(labelBytes.length);                 // VolumeLabelLength
		buf.put((byte) 0);                             // SupportsObjects
		buf.put((byte) 0);                             // Reserved
		buf.put(labelBytes);
		return buf.array();
	}

	/** MS-FSCC 2.5.8 — 24 bytes. */
	static byte[] sizeInfo(FsSize size) {
		var buf = alloc(24);
		buf.putLong(size.totalAllocationUnits());
		buf.putLong(size.availableAllocationUnits());
		buf.putInt(size.sectorsPerAllocationUnit());
		buf.putInt(size.bytesPerSector());
		return buf.array();
	}

	/** MS-FSCC 2.5.10 — 8 bytes, advertises a remote disk volume. */
	static byte[] deviceInfo() {
		var buf = alloc(8);
		buf.putInt(DEVICE_TYPE_DISK);
		buf.putInt(DEVICE_CHARACTERISTICS_REMOTE);
		return buf.array();
	}

	/**
	 * MS-FSCC 2.5.1 — {@code FileSystemAttributes(4) + MaximumComponentNameLength(4) +
	 * FileSystemNameLength(4) + FileSystemName(UTF-16LE, variable)}.
	 */
	static byte[] attributeInfo(FsAttributes attrs) {
		byte[] nameBytes = attrs.fileSystemName().getBytes(StandardCharsets.UTF_16LE);
		var buf = alloc(12 + nameBytes.length);
		buf.putInt(attrs.fileSystemAttributes());
		buf.putInt(attrs.maxComponentLength());
		buf.putInt(nameBytes.length);
		buf.put(nameBytes);
		return buf.array();
	}

	/** MS-FSCC 2.5.4 — 32 bytes. CallerAvailable == ActualAvailable (no per-user quotas). */
	static byte[] fullSizeInfo(FsSize size) {
		var buf = alloc(32);
		buf.putLong(size.totalAllocationUnits());
		buf.putLong(size.availableAllocationUnits());       // CallerAvailable
		buf.putLong(size.availableAllocationUnits());       // ActualAvailable
		buf.putInt(size.sectorsPerAllocationUnit());
		buf.putInt(size.bytesPerSector());
		return buf.array();
	}

	/**
	 * Deterministic 32-bit volume serial derived from the label. Windows typically uses a random
	 * value chosen at format time; for a virtual share a hash is stable enough.
	 */
	private static int volumeSerial(String label) {
		int h = 0x9E3779B1;
		for (int i = 0; i < label.length(); i++) {
			h = 31 * h + label.charAt(i);
		}
		return h;
	}

	private static ByteBuffer alloc(int size) {
		return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
	}
}
