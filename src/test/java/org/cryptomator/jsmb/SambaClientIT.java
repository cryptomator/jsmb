package org.cryptomator.jsmb;

import org.cryptomator.jsmb.share.nio.NioShare;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.simple.SimpleLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/**
 * Manual harness for driving jSMB with Samba's {@code smbclient} from a Podman container.
 * Augments the {@code smbj}-based integration tests — gated on the {@code samba.harness}
 * system property, which the {@code samba-harness} Maven profile sets for you:
 * <pre>{@code
 *     mvn verify -Psamba-harness
 * }</pre>
 * A plain {@code mvn test} skips this class. In a second terminal run the {@code podman run}
 * command this test logs at startup; hit Enter / {@code Ctrl-D} to shut the server down.
 * <p>
 * Enables {@link Config#ENCRYPT_DATA}, {@link Config#REQUIRE_MESSAGE_SIGNING} and
 * {@link Config#DEBUG_ENCRYPTION} so Wireshark can decrypt the captured session (see the
 * "Debugging" section of {@code README.md} for the paste-format and preference path).
 */
public class SambaClientIT {

	static {
		System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "DEBUG");
	}

	private static final Logger LOG = LoggerFactory.getLogger(SambaClientIT.class);
	// 4446 rather than 4445 — macOS reserves 4445 for `upnotifyp` (Apple Push Notifications), which
	// collides with our harness. Keep RunIT on 4445 (IDE users can still use it when 4445 is free).
	private static final int PORT = 4446;
	private static final String SHARE_NAME = "data";

	@TempDir
	static Path shareRoot;

	@Test
	@EnabledIfSystemProperty(named = "samba.harness", matches = "true",
			disabledReason = "run with `mvn verify -Psamba-harness` to drive jSMB with Samba's smbclient from a Podman container")
	@DisplayName("Run TcpServer on port 4446 for interactive Samba smbclient testing")
	public void test() {
		var config = Config.create(Config.ENCRYPT_DATA, Config.REQUIRE_MESSAGE_SIGNING, Config.DEBUG_ENCRYPTION);
		try (var server = TcpServer.start(PORT, config, new Credentials("DOMAIN", "user", "password"))) {
			server.registerShare(SHARE_NAME, new NioShare(shareRoot));
			seedFixtures();
			logInvocationHelp(server.getLocalPort());

			// wait for SIGTERM:
			var stop = new CountDownLatch(1);
			Runtime.getRuntime().addShutdownHook(new Thread(stop::countDown, "shutdown"));
			stop.await();
			LOG.info("Shutting down...");
		} catch (IOException e) {
			LOG.error("Server error", e);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			LOG.error("Thread interrupted", e);
		}
	}

	/**
	 * Drops a handful of files into the share root so READ-dependent scenarios (e.g. {@code get}) have something to
	 * fetch before WRITE (M9) lands and lets {@code smbclient} do its own {@code put}.
	 */
	private static void seedFixtures() throws IOException {
		Files.writeString(shareRoot.resolve("greeting.txt"), "Hello from jSMB! This is a pre-seeded fixture for the READ scenario.\n");
	}

	private static void logInvocationHelp(int port) {
		LOG.info("jSMB share '{}' is backed by {}", SHARE_NAME, shareRoot);
		LOG.info("Ready to accept connections on localhost:{}", port);
		LOG.info("");
		LOG.info("Run Samba's smbclient in a Podman container (choose the variant for your OS):");
		LOG.info("");
		LOG.info("  Linux (native Podman, '--network host' reaches the host directly):");
		LOG.info("    podman run --rm -it --network host \\");
		LOG.info("      docker.io/library/alpine:latest sh -c \\");
		LOG.info("      'apk add --no-cache samba-client && \\");
		LOG.info("       smbclient -d 10 -p {} -U DOMAIN/user%password //localhost/{}'", port, SHARE_NAME);
		LOG.info("");
		LOG.info("  macOS / Windows (Podman machine — 'host.containers.internal' is the host gateway):");
		LOG.info("    podman run --rm -it \\");
		LOG.info("      docker.io/library/alpine:latest sh -c \\");
		LOG.info("      'apk add --no-cache samba-client && \\");
		LOG.info("       smbclient -d 10 -p {} -U DOMAIN/user%password //host.containers.internal/{}'", port, SHARE_NAME);
		LOG.info("");
		LOG.info("Useful smbclient commands once connected: ls, cd, get, put, mkdir, rm, exit.");
		LOG.info("Ctrl-C to stop the server.");
	}
}
