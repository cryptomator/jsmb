package org.cryptomator.jsmb.smb2.tree;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.FsAttributes;
import org.cryptomator.jsmb.share.FsSize;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.SmbOpen;
import org.cryptomator.jsmb.share.SmbShare;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.Global;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.Session;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

class TreeConnectHandlerTest {

	private Global global;
	private Connection connection;
	private Session session;
	private SmbShare share;
	private TreeConnectHandler handler;

	@BeforeEach
	void setUp() {
		global = new Global(Config.DEFAULT);
		connection = new Connection(global);
		share = new StubShare();
		global.shares.put("data", share);
		// minimal session creation — bypass the full Negotiator flow
		session = Session.create(connection);
		session.signingRequired = true;
		handler = new TreeConnectHandler(connection);
	}

	@Test
	@DisplayName("TREE_CONNECT to a registered share returns success and allocates a tree id")
	void connectSucceedsAndAllocatesTreeId() {
		var request = buildConnectRequest(session.sessionId, "\\\\localhost\\data");

		var response = handler.connect(request);

		Assertions.assertInstanceOf(TreeConnectResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertEquals(Command.TREE_CONNECT.value(), response.header().command());
		Assertions.assertNotEquals(0, response.header().treeId());
		Assertions.assertEquals(1, session.treeConnectTable.size());

		var stored = session.treeConnectTable.get(response.header().treeId());
		Assertions.assertSame(share, stored.share());
		Assertions.assertEquals("data", stored.shareName());
	}

	@Test
	@DisplayName("Share lookup is case-insensitive (real clients send UPPER-case)")
	void shareLookupIsCaseInsensitive() {
		var response = handler.connect(buildConnectRequest(session.sessionId, "\\\\localhost\\DATA"));

		Assertions.assertInstanceOf(TreeConnectResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		var stored = session.treeConnectTable.get(response.header().treeId());
		Assertions.assertSame(share, stored.share());
	}

	@Test
	@DisplayName("TREE_CONNECT to an unknown share returns STATUS_BAD_NETWORK_NAME")
	void connectUnknownShareIsRejected() {
		var request = buildConnectRequest(session.sessionId, "\\\\localhost\\missing");

		var response = handler.connect(request);

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_BAD_NETWORK_NAME, response.header().status());
		Assertions.assertTrue(session.treeConnectTable.isEmpty());
	}

	@Test
	@DisplayName("TREE_CONNECT when session is unknown returns STATUS_USER_SESSION_DELETED")
	void connectWithUnknownSession() {
		var request = buildConnectRequest(0xDEADBEEFL, "\\\\localhost\\data");

		var response = handler.connect(request);

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_USER_SESSION_DELETED, response.header().status());
	}

	@Test
	@DisplayName("Sequential tree-connects on the same session get distinct tree ids")
	void sequentialConnectsGetDistinctTreeIds() {
		global.shares.put("more", new StubShare());

		var first = handler.connect(buildConnectRequest(session.sessionId, "\\\\localhost\\data"));
		var second = handler.connect(buildConnectRequest(session.sessionId, "\\\\localhost\\more"));

		Assertions.assertNotEquals(first.header().treeId(), second.header().treeId());
		Assertions.assertEquals(2, session.treeConnectTable.size());
	}

	@Test
	@DisplayName("TREE_CONNECT to IPC$ succeeds with ShareType=PIPE and a null backend")
	void ipcDollarIsAcceptedAsPipeTree() {
		var request = buildConnectRequest(session.sessionId, "\\\\localhost\\IPC$");

		var response = handler.connect(request);

		Assertions.assertInstanceOf(TreeConnectResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertEquals(TreeConnectResponse.SHARE_TYPE_PIPE, response.segment().get(Layouts.BYTE, 2));
		var stored = session.treeConnectTable.get(response.header().treeId());
		Assertions.assertEquals("IPC$", stored.shareName());
		Assertions.assertNull(stored.share(), "IPC$ tree carries no disk backend");
	}

	@Test
	@DisplayName("IPC$ match is case-insensitive (client may send 'ipc$')")
	void ipcDollarLowercase() {
		var response = handler.connect(buildConnectRequest(session.sessionId, "\\\\localhost\\ipc$"));

		Assertions.assertInstanceOf(TreeConnectResponse.class, response);
		Assertions.assertEquals(TreeConnectResponse.SHARE_TYPE_PIPE, response.segment().get(Layouts.BYTE, 2));
	}

	@Test
	@DisplayName("TREE_DISCONNECT removes the entry and returns success")
	void disconnectRemovesTreeConnect() {
		var connect = handler.connect(buildConnectRequest(session.sessionId, "\\\\localhost\\data"));
		int treeId = connect.header().treeId();

		var response = handler.disconnect(buildDisconnectRequest(session.sessionId, treeId));

		Assertions.assertInstanceOf(TreeDisconnectResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertTrue(session.treeConnectTable.isEmpty());
	}

	@Test
	@DisplayName("TREE_DISCONNECT of an unknown tree id returns STATUS_NETWORK_NAME_DELETED")
	void disconnectUnknownTreeId() {
		var response = handler.disconnect(buildDisconnectRequest(session.sessionId, 0x12345));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_NETWORK_NAME_DELETED, response.header().status());
	}

	@Test
	@DisplayName("shareNameOf extracts the last path component after backslashes")
	void shareNameExtraction() {
		Assertions.assertEquals("data", TreeConnectHandler.shareNameOf("\\\\localhost\\data"));
		Assertions.assertEquals("data", TreeConnectHandler.shareNameOf("data"));
		Assertions.assertEquals("", TreeConnectHandler.shareNameOf("\\\\server\\"));
	}

	private static TreeConnectRequest buildConnectRequest(long sessionId, String path) {
		byte[] pathBytes = path.getBytes(StandardCharsets.UTF_16LE);

		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.TREE_CONNECT.value());
		headerSeg.set(Layouts.LE_INT64, 40, sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[8 + pathBytes.length]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 9);
		bodySeg.set(Layouts.LE_UINT16, 4, (char) (PacketHeader.STRUCTURE_SIZE + 8));
		bodySeg.set(Layouts.LE_UINT16, 6, (char) pathBytes.length);
		bodySeg.asSlice(8, pathBytes.length).copyFrom(MemorySegment.ofArray(pathBytes));

		return new TreeConnectRequest(new PacketHeader(headerSeg), bodySeg);
	}

	private static TreeDisconnectRequest buildDisconnectRequest(long sessionId, int treeId) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.TREE_DISCONNECT.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeId);
		headerSeg.set(Layouts.LE_INT64, 40, sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[4]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 4);
		return new TreeDisconnectRequest(new PacketHeader(headerSeg), bodySeg);
	}

	/**
	 * Minimal test-only {@link SmbShare} — the handler never touches its methods, it only stores
	 * the reference. Avoids Mockito's inline-mock-maker which currently can't instrument some
	 * classes under JDK 25.
	 */
	private static final class StubShare implements SmbShare {
		@Override
		public SmbOpen open(String path, OpenParams params) {
			throw new UnsupportedOperationException();
		}

		@Override
		public FsAttributes fsAttributes() {
			throw new UnsupportedOperationException();
		}

		@Override
		public FsSize fsSize() {
			throw new UnsupportedOperationException();
		}
	}
}
