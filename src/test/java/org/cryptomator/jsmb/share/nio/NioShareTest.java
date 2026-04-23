package org.cryptomator.jsmb.share.nio;

import org.cryptomator.jsmb.share.DirEntry;
import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.OpenParams;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

class NioShareTest {

	private static final OpenParams OPEN_READWRITE = new OpenParams(0, 0, OpenParams.Disposition.OPEN, 0);
	private static final OpenParams CREATE_FILE = new OpenParams(0, 0, OpenParams.Disposition.CREATE, 0);
	private static final OpenParams CREATE_DIR = new OpenParams(0, 0, OpenParams.Disposition.CREATE, OpenParams.OPTION_DIRECTORY_FILE);
	private static final OpenParams OPEN_IF_FILE = new OpenParams(0, 0, OpenParams.Disposition.OPEN_IF, 0);
	private static final OpenParams OPEN_IF_DIR = new OpenParams(0, 0, OpenParams.Disposition.OPEN_IF, OpenParams.OPTION_DIRECTORY_FILE);
	private static final OpenParams OVERWRITE_IF = new OpenParams(0, 0, OpenParams.Disposition.OVERWRITE_IF, 0);

	@Nested
	@DisplayName("open")
	class OpenTests {

		@Test
		@DisplayName("OPEN on a missing file throws NoSuchFileException")
		void openMissingFileFails(@TempDir Path root) {
			var share = new NioShare(root);
			Assertions.assertThrows(NoSuchFileException.class, () -> share.open("missing.txt", OPEN_READWRITE));
		}

		@Test
		@DisplayName("CREATE on an existing file throws FileAlreadyExistsException")
		void createExistingFileFails(@TempDir Path root) throws IOException {
			Files.createFile(root.resolve("already-here.txt"));
			var share = new NioShare(root);
			Assertions.assertThrows(FileAlreadyExistsException.class, () -> share.open("already-here.txt", CREATE_FILE));
		}

		@Test
		@DisplayName("CREATE creates a new file on disk and returns an open handle")
		void createFileMaterializesOnDisk(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("new.txt", CREATE_FILE)) {
				Assertions.assertNotNull(open.fileId());
				Assertions.assertTrue(Files.isRegularFile(root.resolve("new.txt")));
				Assertions.assertFalse(open.queryStandard().directory());
			}
		}

		@Test
		@DisplayName("CREATE with OPTION_DIRECTORY_FILE creates a directory")
		void createDirectoryMaterializesOnDisk(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("subdir", CREATE_DIR)) {
				Assertions.assertTrue(Files.isDirectory(root.resolve("subdir")));
				Assertions.assertTrue(open.queryStandard().directory());
			}
		}

		@Test
		@DisplayName("OPEN_IF returns the existing entry when present")
		void openIfReturnsExisting(@TempDir Path root) throws IOException {
			Files.writeString(root.resolve("existing.txt"), "hello");
			var share = new NioShare(root);
			try (var open = share.open("existing.txt", OPEN_IF_FILE)) {
				Assertions.assertEquals(5L, open.queryStandard().endOfFile());
			}
		}

		@Test
		@DisplayName("Leading slash in path is tolerated")
		void leadingSlashIsStripped(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var _ = share.open("/leading.txt", CREATE_FILE)) {
				Assertions.assertTrue(Files.exists(root.resolve("leading.txt")));
			}
		}
	}

	@Nested
	@DisplayName("read / write / flush")
	class IoTests {

		@Test
		@DisplayName("Writing at an offset and reading it back returns the same bytes")
		void writeThenReadRoundtrips(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			byte[] payload = "The quick brown fox".getBytes(StandardCharsets.UTF_8);
			try (var open = share.open("file.bin", CREATE_FILE)) {
				int written = open.write(ByteBuffer.wrap(payload), 0);
				Assertions.assertEquals(payload.length, written);
				open.flush();

				var readBuf = ByteBuffer.allocate(payload.length);
				int read = open.read(readBuf, 0);
				Assertions.assertEquals(payload.length, read);
				Assertions.assertArrayEquals(payload, readBuf.array());
			}
		}

		@Test
		@DisplayName("read returns -1 once the offset is past end-of-file")
		void readPastEofReturnsMinusOne(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			Files.writeString(root.resolve("small.txt"), "abc");
			try (var open = share.open("small.txt", OPEN_IF_FILE)) {
				var buf = ByteBuffer.allocate(8);
				int read = open.read(buf, 100);
				Assertions.assertEquals(-1, read);
			}
		}

		@Test
		@DisplayName("read / write on a directory handle throws UnsupportedOperationException")
		void readWriteOnDirectoryThrows(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("adir", CREATE_DIR)) {
				Assertions.assertThrows(UnsupportedOperationException.class, () -> open.read(ByteBuffer.allocate(1), 0));
				Assertions.assertThrows(UnsupportedOperationException.class, () -> open.write(ByteBuffer.allocate(1), 0));
			}
		}

		@Test
		@DisplayName("setEndOfFile truncates when shrinking and extends with zeros when growing")
		void setEndOfFileTruncatesAndExtends(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("resize.bin", CREATE_FILE)) {
				open.write(ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}), 0);
				open.setEndOfFile(4);
				Assertions.assertEquals(4L, open.queryStandard().endOfFile());

				open.setEndOfFile(10);
				Assertions.assertEquals(10L, open.queryStandard().endOfFile());
			}
		}
	}

	@Nested
	@DisplayName("rename / delete-on-close")
	class MutationTests {

		@Test
		@DisplayName("rename moves the target on disk")
		void renameMovesFile(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("original.txt", CREATE_FILE)) {
				open.rename("renamed.txt", false);
			}
			Assertions.assertFalse(Files.exists(root.resolve("original.txt")));
			Assertions.assertTrue(Files.exists(root.resolve("renamed.txt")));
		}

		@Test
		@DisplayName("markForDeletion + close removes the file")
		void deleteOnCloseRemovesFile(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("doomed.txt", CREATE_FILE)) {
				open.markForDeletion();
			}
			Assertions.assertFalse(Files.exists(root.resolve("doomed.txt")));
		}

		@Test
		@DisplayName("OVERWRITE_IF creates when missing")
		void overwriteIfCreatesWhenMissing(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("fresh.txt", OVERWRITE_IF)) {
				Assertions.assertEquals(0L, open.queryStandard().endOfFile());
			}
			Assertions.assertTrue(Files.exists(root.resolve("fresh.txt")));
		}
	}

	@Nested
	@DisplayName("query / set basic info")
	class InfoTests {

		@Test
		@DisplayName("queryBasic for a file sets ATTR_NORMAL; for a directory sets ATTR_DIRECTORY")
		void attributesReflectType(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var file = share.open("file.bin", CREATE_FILE);
				 var dir = share.open("dir", CREATE_DIR)) {
				Assertions.assertEquals(FileBasicInfo.ATTR_NORMAL, file.queryBasic().fileAttributes());
				Assertions.assertEquals(FileBasicInfo.ATTR_DIRECTORY, dir.queryBasic().fileAttributes());
			}
		}

		@Test
		@DisplayName("setBasic updates the last-write timestamp")
		void setBasicUpdatesTimestamps(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("stamp.txt", CREATE_FILE)) {
				var target = java.time.Instant.parse("2020-01-02T03:04:05Z");
				open.setBasic(new FileBasicInfo(null, null, target, null, 0));
				Assertions.assertEquals(target, open.queryBasic().lastWriteTime());
			}
		}
	}

	@Nested
	@DisplayName("listChildren")
	class DirectoryTests {

		@Test
		@DisplayName("listChildren on a populated share root yields every entry plus the synthetic '.' (no '..' at the share root)")
		void listsAllChildren(@TempDir Path root) throws IOException {
			Files.writeString(root.resolve("a.txt"), "a");
			Files.writeString(root.resolve("b.txt"), "bb");
			Files.createDirectory(root.resolve("sub"));
			var share = new NioShare(root);
			try (var dir = share.open("", OPEN_IF_DIR);
				 var entries = dir.listChildren(null)) {
				var names = entries.map(DirEntry::name).sorted().toList();
				Assertions.assertEquals(java.util.List.of(".", "a.txt", "b.txt", "sub"), names);
			}
		}

		@Test
		@DisplayName("listChildren on a sub-directory yields '.' and '..' pseudo-entries")
		void listsPseudoEntriesOnSubdirectory(@TempDir Path root) throws IOException {
			Files.createDirectory(root.resolve("sub"));
			Files.writeString(root.resolve("sub").resolve("child.txt"), "x");
			var share = new NioShare(root);
			try (var dir = share.open("sub", OPEN_IF_DIR);
				 var entries = dir.listChildren(null)) {
				var names = entries.map(DirEntry::name).sorted().toList();
				Assertions.assertEquals(java.util.List.of(".", "..", "child.txt"), names);
			}
		}

		@Test
		@DisplayName("listChildren on an empty share root still yields the synthetic '.' entry")
		void listsPseudoEntriesOnEmptyShareRoot(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var dir = share.open("", OPEN_IF_DIR);
				 var entries = dir.listChildren(null)) {
				var names = entries.map(DirEntry::name).toList();
				Assertions.assertEquals(java.util.List.of("."), names);
			}
		}

		@Test
		@DisplayName("listChildren with a glob pattern restricts results")
		void listsChildrenMatchingGlob(@TempDir Path root) throws IOException {
			Files.writeString(root.resolve("one.txt"), "");
			Files.writeString(root.resolve("two.md"), "");
			var share = new NioShare(root);
			try (var dir = share.open("", OPEN_IF_DIR);
				 var entries = dir.listChildren("*.txt")) {
				var names = entries.map(DirEntry::name).toList();
				Assertions.assertEquals(java.util.List.of("one.txt"), names);
			}
		}

		@Test
		@DisplayName("listChildren on a file handle throws UnsupportedOperationException")
		void listChildrenOnFileThrows(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var open = share.open("file.txt", CREATE_FILE)) {
				Assertions.assertThrows(UnsupportedOperationException.class, () -> open.listChildren(null));
			}
		}
	}

	@Nested
	@DisplayName("filesystem-level info")
	class FsTests {

		@Test
		@DisplayName("fsAttributes declares NTFS-like flags and the configured filesystem name")
		void fsAttributesExposesFlags(@TempDir Path root) {
			var share = new NioShare(root, "jsmbfs");
			var attrs = share.fsAttributes();
			Assertions.assertEquals("jsmbfs", attrs.fileSystemName());
			Assertions.assertEquals(255, attrs.maxComponentLength());
			Assertions.assertNotEquals(0, attrs.fileSystemAttributes());
		}

		@Test
		@DisplayName("fsSize returns positive total and non-negative available space")
		void fsSizeIsPositive(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			var size = share.fsSize();
			Assertions.assertTrue(size.totalAllocationUnits() > 0);
			Assertions.assertTrue(size.availableAllocationUnits() >= 0);
			Assertions.assertTrue(size.bytesPerSector() > 0);
		}
	}

	@Nested
	@DisplayName("FileId")
	class FileIdTests {

		@Test
		@DisplayName("Each open gets a unique FileId")
		void fileIdsAreUnique(@TempDir Path root) throws IOException {
			var share = new NioShare(root);
			try (var a = share.open("a.txt", CREATE_FILE);
				 var b = share.open("b.txt", CREATE_FILE)) {
				Assertions.assertNotEquals(a.fileId(), b.fileId());
			}
		}
	}
}
