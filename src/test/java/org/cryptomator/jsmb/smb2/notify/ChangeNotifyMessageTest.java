package org.cryptomator.jsmb.smb2.notify;

import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class ChangeNotifyMessageTest {

	@Test
	@DisplayName("ChangeNotifyRequest accessors read the 32-byte fixed structure")
	void accessors() {
		var seg = MemorySegment.ofArray(new byte[32]);
		seg.set(Layouts.LE_UINT16, 0, (char) 32);
		seg.set(Layouts.LE_UINT16, 2, (char) 0x0001); // Flags = SMB2_WATCH_TREE
		seg.set(Layouts.LE_INT32, 4, 0x10000);         // OutputBufferLength
		seg.set(Layouts.LE_INT64, 8, 0x1122334455667788L);
		seg.set(Layouts.LE_INT64, 16, 0x99AABBCCDDEEFF00L);
		seg.set(Layouts.LE_INT32, 24, 0x0000001F);     // CompletionFilter = all file + dir changes

		var request = new ChangeNotifyRequest(null, seg);

		Assertions.assertEquals(32, request.structureSize());
		Assertions.assertEquals(0x0001, request.flags());
		Assertions.assertEquals(0x10000, request.outputBufferLength());
		Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
		Assertions.assertEquals(0x99AABBCCDDEEFF00L, request.fileId().volatileHandle());
		Assertions.assertEquals(0x0000001F, request.completionFilter());
	}

	@Test
	@DisplayName("fileId(FileId) writes the FileId back at offset 8 for sentinel substitution in compound chains")
	void fileIdSetter() {
		var seg = MemorySegment.ofArray(new byte[32]);
		seg.set(Layouts.LE_UINT16, 0, (char) 32);
		var request = new ChangeNotifyRequest(null, seg);

		request.fileId(new FileId(0xFACEL, 0xFEEDL));

		Assertions.assertEquals(0xFACEL, seg.get(Layouts.LE_INT64, 8));
		Assertions.assertEquals(0xFEEDL, seg.get(Layouts.LE_INT64, 16));
	}
}
