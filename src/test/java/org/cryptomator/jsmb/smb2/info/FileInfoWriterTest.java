package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.WinFileTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

class FileInfoWriterTest {

	private static final Instant CREATED = Instant.parse("2020-01-02T03:04:05Z");
	private static final Instant ACCESSED = Instant.parse("2021-02-03T04:05:06Z");
	private static final Instant WRITTEN = Instant.parse("2022-03-04T05:06:07Z");
	private static final Instant CHANGED = Instant.parse("2023-04-05T06:07:08Z");

	private static final FileBasicInfo BASIC = new FileBasicInfo(CREATED, ACCESSED, WRITTEN, CHANGED, FileBasicInfo.ATTR_NORMAL);
	private static final FileStandardInfo STD = new FileStandardInfo(4096L, 1234L, 1, false, false);

	@Test
	@DisplayName("FileBasicInformation: 40 bytes, timestamps + attrs")
	void basicInfo() {
		byte[] bytes = FileInfoWriter.basicInfo(BASIC);
		Assertions.assertEquals(40, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(WinFileTime.fromInstant(CREATED), seg.get(Layouts.LE_INT64, 0));
		Assertions.assertEquals(WinFileTime.fromInstant(CHANGED), seg.get(Layouts.LE_INT64, 24));
		Assertions.assertEquals(FileBasicInfo.ATTR_NORMAL, seg.get(Layouts.LE_INT32, 32));
	}

	@Test
	@DisplayName("FileStandardInformation: 24 bytes, sizes + flags")
	void standardInfo() {
		byte[] bytes = FileInfoWriter.standardInfo(STD);
		Assertions.assertEquals(24, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(4096L, seg.get(Layouts.LE_INT64, 0));
		Assertions.assertEquals(1234L, seg.get(Layouts.LE_INT64, 8));
		Assertions.assertEquals(1, seg.get(Layouts.LE_INT32, 16));
		Assertions.assertEquals(0, seg.get(Layouts.BYTE, 20));
		Assertions.assertEquals(0, seg.get(Layouts.BYTE, 21));
	}

	@Test
	@DisplayName("FileStandardInformation: deletePending + directory bits map correctly")
	void standardInfoBits() {
		var delPending = new FileStandardInfo(0, 0, 1, true, false);
		Assertions.assertEquals(1, MemorySegment.ofArray(FileInfoWriter.standardInfo(delPending)).get(Layouts.BYTE, 20));

		var dir = new FileStandardInfo(0, 0, 1, false, true);
		Assertions.assertEquals(1, MemorySegment.ofArray(FileInfoWriter.standardInfo(dir)).get(Layouts.BYTE, 21));
	}

	@Test
	@DisplayName("FileInternalInformation: 8-byte IndexNumber is stable for the same path")
	void internalInfoStable() {
		Assertions.assertArrayEquals(FileInfoWriter.internalInfo("some/path"), FileInfoWriter.internalInfo("some/path"));
		Assertions.assertFalse(java.util.Arrays.equals(FileInfoWriter.internalInfo("a"), FileInfoWriter.internalInfo("b")));
	}

	@Test
	@DisplayName("FileEaInformation / FilePositionInformation / FileModeInformation / FileAlignmentInformation are zero-filled")
	void zeroFilled() {
		Assertions.assertArrayEquals(new byte[4], FileInfoWriter.eaInfo());
		Assertions.assertArrayEquals(new byte[8], FileInfoWriter.positionInfo());
		Assertions.assertArrayEquals(new byte[4], FileInfoWriter.modeInfo());
		Assertions.assertArrayEquals(new byte[4], FileInfoWriter.alignmentInfo());
	}

	@Test
	@DisplayName("FileAccessInformation reports FILE_ALL_ACCESS")
	void accessInfo() {
		byte[] bytes = FileInfoWriter.accessInfo();
		Assertions.assertEquals(4, bytes.length);
		Assertions.assertEquals(0x001F01FF, MemorySegment.ofArray(bytes).get(Layouts.LE_INT32, 0));
	}

	@Test
	@DisplayName("FileNameInformation encodes the absolute-from-share-root backslash path")
	void nameInfo() {
		byte[] bytes = FileInfoWriter.nameInfo("sub/file.txt");
		var seg = MemorySegment.ofArray(bytes);
		int len = seg.get(Layouts.LE_INT32, 0);
		var name = new String(bytes, 4, len, StandardCharsets.UTF_16LE);
		Assertions.assertEquals("\\sub\\file.txt", name);
	}

	@Test
	@DisplayName("FileNameInformation renders the share root as a single backslash")
	void nameInfoRoot() {
		byte[] bytes = FileInfoWriter.nameInfo("");
		int len = MemorySegment.ofArray(bytes).get(Layouts.LE_INT32, 0);
		Assertions.assertEquals("\\", new String(bytes, 4, len, StandardCharsets.UTF_16LE));
	}

	@Test
	@DisplayName("FileNetworkOpenInformation: 56 bytes, packed times + sizes + attrs")
	void networkOpenInfo() {
		byte[] bytes = FileInfoWriter.networkOpenInfo(BASIC, STD);
		Assertions.assertEquals(56, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(WinFileTime.fromInstant(CREATED), seg.get(Layouts.LE_INT64, 0));
		Assertions.assertEquals(4096L, seg.get(Layouts.LE_INT64, 32));
		Assertions.assertEquals(1234L, seg.get(Layouts.LE_INT64, 40));
		Assertions.assertEquals(FileBasicInfo.ATTR_NORMAL, seg.get(Layouts.LE_INT32, 48));
	}

	@Test
	@DisplayName("FileAttributeTagInformation: 8 bytes, attrs + ReparseTag=0")
	void attributeTagInfo() {
		byte[] bytes = FileInfoWriter.attributeTagInfo(BASIC);
		Assertions.assertEquals(8, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		Assertions.assertEquals(FileBasicInfo.ATTR_NORMAL, seg.get(Layouts.LE_INT32, 0));
		Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, 4));
	}

	@Test
	@DisplayName("FileStreamInformation is empty (no NTFS alternate streams)")
	void streamInfo() {
		Assertions.assertEquals(0, FileInfoWriter.streamInfo().length);
	}

	@Test
	@DisplayName("FileAllInformation concatenates Basic + Standard + Internal + Ea + Access + Position + Mode + Alignment + Name")
	void allInfoComposite() {
		byte[] bytes = FileInfoWriter.allInfo("file.txt", BASIC, STD);
		byte[] nameBytes = "\\file.txt".getBytes(StandardCharsets.UTF_16LE);
		Assertions.assertEquals(96 + 4 + nameBytes.length, bytes.length);
		var seg = MemorySegment.ofArray(bytes);
		// Basic header at offset 0
		Assertions.assertEquals(WinFileTime.fromInstant(CREATED), seg.get(Layouts.LE_INT64, 0));
		// Standard header at offset 40
		Assertions.assertEquals(4096L, seg.get(Layouts.LE_INT64, 40));
		// Internal at offset 64
		Assertions.assertNotEquals(0L, seg.get(Layouts.LE_INT64, 64));
		// Access at offset 76
		Assertions.assertEquals(0x001F01FF, seg.get(Layouts.LE_INT32, 76));
		// Name length at offset 96
		Assertions.assertEquals(nameBytes.length, seg.get(Layouts.LE_INT32, 96));
	}
}
