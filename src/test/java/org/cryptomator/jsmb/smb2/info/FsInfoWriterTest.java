package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FsAttributes;
import org.cryptomator.jsmb.share.FsSize;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

class FsInfoWriterTest {

	private static final FsSize SIZE = new FsSize(10_000L, 6_000L, 8, 4096);
	private static final FsAttributes ATTRS = new FsAttributes(
			FsAttributes.FS_ATTR_CASE_SENSITIVE_SEARCH | FsAttributes.FS_ATTR_UNICODE_ON_DISK,
			255,
			"NTFS");

	@Test
	@DisplayName("FileFsFullSizeInformation: 32 bytes; caller + actual available units both reflect FsSize.availableAllocationUnits")
	void fullSizeInfo() {
		byte[] bytes = FsInfoWriter.fullSizeInfo(SIZE);
		Assertions.assertEquals(32, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(10_000L, seg.get(Layouts.LE_INT64, 0));
		Assertions.assertEquals(6_000L, seg.get(Layouts.LE_INT64, 8));    // CallerAvailable
		Assertions.assertEquals(6_000L, seg.get(Layouts.LE_INT64, 16));   // ActualAvailable
		Assertions.assertEquals(8, seg.get(Layouts.LE_INT32, 24));
		Assertions.assertEquals(4096, seg.get(Layouts.LE_INT32, 28));
	}

	@Test
	@DisplayName("FileFsSizeInformation: 24 bytes with total/available/sectors/bytes")
	void sizeInfo() {
		byte[] bytes = FsInfoWriter.sizeInfo(SIZE);
		Assertions.assertEquals(24, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(10_000L, seg.get(Layouts.LE_INT64, 0));
		Assertions.assertEquals(6_000L, seg.get(Layouts.LE_INT64, 8));
		Assertions.assertEquals(8, seg.get(Layouts.LE_INT32, 16));
		Assertions.assertEquals(4096, seg.get(Layouts.LE_INT32, 20));
	}

	@Test
	@DisplayName("FileFsAttributeInformation: flags + max-component + UTF-16LE filesystem name")
	void attributeInfo() {
		byte[] bytes = FsInfoWriter.attributeInfo(ATTRS);
		var seg = MemorySegment.ofArray(bytes);
		int flags = seg.get(Layouts.LE_INT32, 0);
		Assertions.assertNotEquals(0, flags & FsAttributes.FS_ATTR_CASE_SENSITIVE_SEARCH);
		Assertions.assertEquals(255, seg.get(Layouts.LE_INT32, 4));
		int nameLen = seg.get(Layouts.LE_INT32, 8);
		Assertions.assertEquals("NTFS", new String(bytes, 12, nameLen, StandardCharsets.UTF_16LE));
	}

	@Test
	@DisplayName("FileFsDeviceInformation: 8 bytes advertising a remote disk")
	void deviceInfo() {
		byte[] bytes = FsInfoWriter.deviceInfo();
		Assertions.assertEquals(8, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(0x07, seg.get(Layouts.LE_INT32, 0));      // FILE_DEVICE_DISK
		Assertions.assertEquals(0x10, seg.get(Layouts.LE_INT32, 4));      // FILE_REMOTE_DEVICE
	}

	@Test
	@DisplayName("FileFsVolumeInformation: timestamp + serial + label + zero-byte SupportsObjects/Reserved")
	void volumeInfo() {
		long ft = 0x01DAABBCCDDEEFF00L;
		byte[] bytes = FsInfoWriter.volumeInfo("data", ft);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(ft, seg.get(Layouts.LE_INT64, 0));
		Assertions.assertNotEquals(0, seg.get(Layouts.LE_INT32, 8));      // synthetic serial ≠ 0
		int labelLen = seg.get(Layouts.LE_INT32, 12);
		Assertions.assertEquals("data", new String(bytes, 18, labelLen, StandardCharsets.UTF_16LE));
	}
}
