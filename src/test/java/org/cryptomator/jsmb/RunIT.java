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
import java.util.concurrent.CountDownLatch;

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
		try (var server = TcpServer.start(4445, Config.create(Config.DEBUG_ENCRYPTION), new Credentials("DOMAIN", "user", "password"))) {
			server.registerShare("data", new NioShare(shareRoot));
			LOG.info("Registered share 'data' at {}", shareRoot);
			LOG.info("Ready to accept connections on localhost:{} — Ctrl+C to stop", server.getLocalPort());

			// wait for SIGTERM:
			var stop = new CountDownLatch(1);
			Runtime.getRuntime().addShutdownHook(new Thread(stop::countDown, "shutdown"));
			stop.await();
			LOG.info("Shutting down...");
		} catch (IOException e) {
			LOG.error("Server error", e);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			LOG.error("Thread interrupted.", e);
		}
	}
}
