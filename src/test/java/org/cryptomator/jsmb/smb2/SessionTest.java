package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.nio.NioShare;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

class SessionTest {

	@TempDir
	Path shareRoot;

	private Global global;
	private Connection connection;
	private Session session;

	@BeforeEach
	void setUp() {
		global = new Global(Config.DEFAULT, new Credentials("DOMAIN", "user", "password"));
		connection = new Connection(global);
		session = Session.create(connection);
	}

	@Test
	@DisplayName("remove() closes the session's opens")
	void removeClosesOpens() throws IOException {
		var share = new NioShare(shareRoot);
		var treeConnect = new TreeConnect(1, "data", share, 0x001F01FF);
		session.treeConnectTable.put(1, treeConnect);
		// closing the backend handle is what carries out the pending deletion, which makes it observable
		Files.writeString(shareRoot.resolve("pending.txt"), "content");
		var backend = share.open("pending.txt", new OpenParams(0x00130089, 0x00000007, OpenParams.Disposition.OPEN, 0));
		backend.setDeletePending(true);
		session.openTable.put(backend.fileId(), new Open(backend.fileId(), backend, session, treeConnect, "pending.txt", 0));

		session.remove();

		Assertions.assertFalse(Files.exists(shareRoot.resolve("pending.txt")));
		Assertions.assertTrue(session.openTable.isEmpty());
	}

	@Test
	@DisplayName("remove() disconnects the session's tree connects")
	void removeDisconnectsTrees() {
		session.treeConnectTable.put(1, new TreeConnect(1, "data", null, 0));

		session.remove();

		Assertions.assertTrue(session.treeConnectTable.isEmpty());
	}

	@Test
	@DisplayName("remove() takes the session out of the connection's and the global session table")
	void removeDeregisters() {
		session.remove();

		Assertions.assertFalse(connection.sessionTable.containsKey(session.sessionId));
		Assertions.assertFalse(global.sessionTable.containsKey(session.sessionId));
	}
}
