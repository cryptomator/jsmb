package org.cryptomator.jsmb;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class RunIT {

	private static final Logger LOG = LoggerFactory.getLogger(RunIT.class);

	@Test
	@Disabled
	public void test() {
		try (var server = TcpServer.start(4445)){
			LOG.info("Ready to accept connections...");
			System.in.read();
		} catch (IOException e) {
			LOG.error("Server error", e);
		}
	}
}
