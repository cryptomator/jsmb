package org.cryptomator.jsmb;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.simple.SimpleLogger;

import java.io.IOException;

public class RunIT {

	static {
		System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "DEBUG");
	}

	private static final Logger LOG = LoggerFactory.getLogger(RunIT.class);

	@Test
	@Disabled("run manually for interactive client testing")
	@DisplayName("Run TcpServer on port 4445 and block on stdin")
	public void test() {
		try (var server = TcpServer.start(4445)){
			LOG.info("Ready to accept connections...");
			System.in.read();
		} catch (IOException e) {
			LOG.error("Server error", e);
		}
	}
}
