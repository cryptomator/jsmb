package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.share.DirEntry;
import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

class DirectoryInfoWriterTest {

	private static final Instant T = Instant.parse("2026-01-02T03:04:05Z");

	private static DirEntry entry(String name, long size, boolean dir) {
		int attrs = dir ? FileBasicInfo.ATTR_DIRECTORY : FileBasicInfo.ATTR_NORMAL;
		return new DirEntry(name,
				new FileBasicInfo(T, T, T, T, attrs),
				new FileStandardInfo(size, size, 1, false, dir));
	}

	@Nested
	@DisplayName("FILE_ID_BOTH_DIRECTORY_INFORMATION")
	class IdBoth {

		@Test
		@DisplayName("Writes the spec-mandated 104-byte fixed header plus the name, 8-byte aligned")
		void singleEntryLayout() {
			var name = "hello.txt";
			byte[] nameBytes = name.getBytes(StandardCharsets.UTF_16LE);
			int expectedUnaligned = 104 + nameBytes.length;
			int expectedAligned = (expectedUnaligned + 7) & ~7;

			var result = DirectoryInfoWriter.write(
					FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
					List.of(entry(name, 1234, false)),
					0, 4096, false);

			Assertions.assertEquals(1, result.entriesWritten());
			Assertions.assertEquals(expectedAligned, result.buffer().length);
			var seg = MemorySegment.ofArray(result.buffer());
			Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, 0), "NextEntryOffset = 0 for last entry");
			Assertions.assertEquals(nameBytes.length, seg.get(Layouts.LE_INT32, 60), "FileNameLength field");
			Assertions.assertEquals(0, seg.get(Layouts.BYTE, 68), "ShortNameLength = 0");
			var writtenName = new byte[nameBytes.length];
			System.arraycopy(result.buffer(), 104, writtenName, 0, nameBytes.length);
			Assertions.assertArrayEquals(nameBytes, writtenName);
		}

		@Test
		@DisplayName("Chains entries via NextEntryOffset with 8-byte alignment")
		void multipleEntriesChained() {
			var result = DirectoryInfoWriter.write(
					FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
					List.of(entry("a.txt", 1, false), entry("b.txt", 2, false), entry("c.txt", 3, false)),
					0, 4096, false);

			Assertions.assertEquals(3, result.entriesWritten());
			var seg = MemorySegment.ofArray(result.buffer());

			int next1 = seg.get(Layouts.LE_INT32, 0);
			Assertions.assertTrue(next1 > 0 && next1 % 8 == 0, "first NextEntryOffset is positive and 8-byte aligned");
			int next2 = seg.get(Layouts.LE_INT32, next1);
			Assertions.assertTrue(next2 > 0 && next2 % 8 == 0, "second NextEntryOffset is positive and 8-byte aligned");
			Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, next1 + next2), "third (last) entry's NextEntryOffset = 0");
		}
	}

	@Nested
	@DisplayName("Buffer capacity handling")
	class Capacity {

		@Test
		@DisplayName("Stops writing when the next entry won't fit, returns written count")
		void stopsOnCapacity() {
			var entries = List.of(entry("aaaaa.txt", 1, false), entry("bbbbb.txt", 2, false), entry("ccccc.txt", 3, false));
			int oneEntrySize = 104 + "aaaaa.txt".getBytes(StandardCharsets.UTF_16LE).length;
			int alignedOne = (oneEntrySize + 7) & ~7;

			// Room for exactly two entries' worth of space
			var result = DirectoryInfoWriter.write(
					FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
					entries, 0, alignedOne * 2 + 4, false);

			Assertions.assertEquals(2, result.entriesWritten());
		}

		@Test
		@DisplayName("Returns 0 entries when the first one alone is too large")
		void zeroWhenFirstDoesNotFit() {
			var result = DirectoryInfoWriter.write(
					FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
					List.of(entry("file.txt", 1, false)),
					0, 32, false);
			Assertions.assertEquals(0, result.entriesWritten());
			Assertions.assertEquals(0, result.buffer().length);
		}

		@Test
		@DisplayName("SL_RETURN_SINGLE_ENTRY caps at one entry even with room for more")
		void singleEntryCap() {
			var result = DirectoryInfoWriter.write(
					FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
					List.of(entry("a.txt", 1, false), entry("b.txt", 2, false)),
					0, 4096, true);

			Assertions.assertEquals(1, result.entriesWritten());
		}

		@Test
		@DisplayName("startIndex lets the caller resume from a previous page")
		void startIndexResumes() {
			var entries = List.of(entry("a.txt", 1, false), entry("b.txt", 2, false), entry("c.txt", 3, false));

			var page2 = DirectoryInfoWriter.write(
					FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
					entries, 2, 4096, false);

			Assertions.assertEquals(1, page2.entriesWritten());
		}
	}

	@Nested
	@DisplayName("Fixed-header sizes match MS-FSCC")
	class HeaderSizes {

		@Test
		@DisplayName("Each info class carries the spec's fixed header size")
		void headerSizes() {
			Assertions.assertEquals(64, DirectoryInfoWriter.fixedHeaderSize(FileInformationClass.FILE_DIRECTORY_INFORMATION));
			Assertions.assertEquals(68, DirectoryInfoWriter.fixedHeaderSize(FileInformationClass.FILE_FULL_DIRECTORY_INFORMATION));
			Assertions.assertEquals(94, DirectoryInfoWriter.fixedHeaderSize(FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION));
			Assertions.assertEquals(12, DirectoryInfoWriter.fixedHeaderSize(FileInformationClass.FILE_NAMES_INFORMATION));
			Assertions.assertEquals(80, DirectoryInfoWriter.fixedHeaderSize(FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION));
			Assertions.assertEquals(104, DirectoryInfoWriter.fixedHeaderSize(FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION));
		}
	}

	@Nested
	@DisplayName("FILE_NAMES_INFORMATION (compact format)")
	class NamesOnly {

		@Test
		@DisplayName("Writes only the 12-byte header + FileName")
		void compactLayout() {
			var name = "hi";
			byte[] nameBytes = name.getBytes(StandardCharsets.UTF_16LE);
			int expectedAligned = ((12 + nameBytes.length) + 7) & ~7;

			var result = DirectoryInfoWriter.write(
					FileInformationClass.FILE_NAMES_INFORMATION,
					List.of(entry(name, 0, false)),
					0, 4096, false);

			Assertions.assertEquals(1, result.entriesWritten());
			Assertions.assertEquals(expectedAligned, result.buffer().length);
			var seg = MemorySegment.ofArray(result.buffer());
			Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, 0));
			Assertions.assertEquals(nameBytes.length, seg.get(Layouts.LE_INT32, 8));
		}
	}

	@Nested
	@DisplayName("FILE_BOTH_DIRECTORY_INFORMATION (smbclient default)")
	class BothDir {

		@Test
		@DisplayName("Writes the 94-byte fixed header + name with zeroed ShortName")
		void layout() {
			var name = "file.txt";
			byte[] nameBytes = name.getBytes(StandardCharsets.UTF_16LE);
			var result = DirectoryInfoWriter.write(
					FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION,
					List.of(entry(name, 42, false)),
					0, 4096, false);

			Assertions.assertEquals(1, result.entriesWritten());
			var seg = MemorySegment.ofArray(result.buffer());
			Assertions.assertEquals(nameBytes.length, seg.get(Layouts.LE_INT32, 60), "FileNameLength");
			Assertions.assertEquals(0, seg.get(Layouts.BYTE, 68), "ShortNameLength = 0");
			// 24-byte ShortName field should be all zero
			for (int i = 70; i < 94; i++) {
				Assertions.assertEquals(0, seg.get(Layouts.BYTE, i), "ShortName byte " + (i - 70));
			}
			byte[] writtenName = new byte[nameBytes.length];
			System.arraycopy(result.buffer(), 94, writtenName, 0, nameBytes.length);
			Assertions.assertArrayEquals(nameBytes, writtenName);
		}
	}
}
