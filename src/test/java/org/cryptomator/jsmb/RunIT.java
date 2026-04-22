package org.cryptomator.jsmb;

import org.cryptomator.jsmb.share.nio.NioShare;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.simple.SimpleLogger;

import java.io.IOException;
import java.nio.file.Path;

public class RunIT {

	static {
		System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "DEBUG");
	}

	private static final Logger LOG = LoggerFactory.getLogger(RunIT.class);

	@TempDir
	Path shareRoot;

	@Test
	@Disabled("run manually for interactive client testing")
	@DisplayName("Run TcpServer on port 4445 and block on stdin")
	public void test() {
		try (var server = TcpServer.start(4445, Config.create(Config.DEBUG_ENCRYPTION))) {
			server.registerShare("data", new NioShare(shareRoot));
			LOG.info("Registered share 'data' at {}", shareRoot);
			LOG.info("Ready to accept connections on localhost:{} (connect via \\\\localhost:{}\\data)", server.getLocalPort(), server.getLocalPort());
			IO.readln();
		} catch (IOException e) {
			LOG.error("Server error", e);
		}
	}
}
