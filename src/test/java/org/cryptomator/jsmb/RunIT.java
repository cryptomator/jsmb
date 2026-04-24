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
import java.util.Arrays;
import java.util.EnumSet;
import java.util.concurrent.CountDownLatch;

/**
 * Long-running launcher for an in-process {@link Server}. Blocks until SIGTERM so external clients
 * (Samba {@code smbclient}, Finder, Explorer, {@code mount}, …) can drive the server. Gated on the
 * {@code jsmb.harness} system property so it never fires during a plain {@code ./mvnw test}.
 *
 * <h2>Invocations</h2>
 * <p>
 * The Maven {@code run} profile presets the gate; the default port is 4445:
 * <pre>{@code
 *   ./mvnw verify -Prun
 * }</pre>
 * <p>
 * If the default port collides (e.g. macOS's {@code upnotifyp} on 4445), override with
 * {@code -Djsmb.port=<port>} and pass a matching {@code SAMBA_PORT=<port>} to the interop wrapper.
 *
 * <h2>Tunables</h2>
 * All knobs are read from {@code -D} system properties; leave any out to pick up the default.
 * <table>
 *   <caption>Configuration properties</caption>
 *   <tr><th>Property</th><th>Default</th><th>Meaning</th></tr>
 *   <tr><td>{@code jsmb.harness}</td><td>(unset)</td><td>Must be {@code true} to enable this test.</td></tr>
 *   <tr><td>{@code jsmb.port}</td><td>{@code 4445}</td><td>TCP port to bind. Also the interop wrapper's default — override both if the port collides.</td></tr>
 *   <tr><td>{@code jsmb.share}</td><td>{@code data}</td><td>Registered share name.</td></tr>
 *   <tr><td>{@code jsmb.domain}</td><td>{@code DOMAIN}</td><td>NTLMv2 domain.</td></tr>
 *   <tr><td>{@code jsmb.user}</td><td>{@code user}</td><td>NTLMv2 username.</td></tr>
 *   <tr><td>{@code jsmb.password}</td><td>{@code password}</td><td>NTLMv2 password.</td></tr>
 *   <tr><td>{@code jsmb.config}</td><td>{@code ENCRYPT_DATA,REQUIRE_MESSAGE_SIGNING,DEBUG_ENCRYPTION}</td><td>Comma-separated {@link Config} flags.</td></tr>
 *   <tr><td>{@code jsmb.logLevel}</td><td>{@code DEBUG}</td><td>SLF4J SimpleLogger default level.</td></tr>
 * </table>
 * <p>
 * The {@code DEBUG_ENCRYPTION} flag prints derived session / signing / encryption keys in the format
 * Wireshark's SMB2 "Decryption keys" preference expects. See the "Debugging" section of {@code README.md}.
 */
public class RunIT {

	private static final String PROP_PORT = "jsmb.port";
	private static final String PROP_SHARE = "jsmb.share";
	private static final String PROP_DOMAIN = "jsmb.domain";
	private static final String PROP_USER = "jsmb.user";
	private static final String PROP_PASSWORD = "jsmb.password";
	private static final String PROP_CONFIG = "jsmb.config";
	private static final String PROP_LOG_LEVEL = "jsmb.logLevel";

	static {
		System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, System.getProperty(PROP_LOG_LEVEL, "DEBUG"));
	}

	private static final Logger LOG = LoggerFactory.getLogger(RunIT.class);

	@TempDir
	static Path shareRoot;

	@Test
	@EnabledIfSystemProperty(named = "jsmb.harness", matches = "true",  disabledReason = "run with `./mvnw verify -Prun` or `-Djsmb.harness=true`")
	@DisplayName("Run TcpServer configured from -Djsmb.* properties and block on SIGTERM")
	public void test() {
		int port = Integer.parseInt(System.getProperty(PROP_PORT, "4445"));
		String shareName = System.getProperty(PROP_SHARE, "data");
		var credentials = new Credentials(
				System.getProperty(PROP_DOMAIN, "DOMAIN"),
				System.getProperty(PROP_USER, "user"),
				System.getProperty(PROP_PASSWORD, "password"));
		var config = parseConfig(System.getProperty(PROP_CONFIG, "ENCRYPT_DATA,REQUIRE_MESSAGE_SIGNING,DEBUG_ENCRYPTION"));

		try (var server = Server.start(port, config, credentials)) {
			server.registerShare(shareName, new NioShare(shareRoot));
			seedFixtures();

			LOG.info("Ctrl-C to stop the server.");

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

	private static EnumSet<Config> parseConfig(String csv) {
		var flags = Arrays.stream(csv.split(","))
				.map(String::trim)
				.filter(s -> !s.isEmpty())
				.map(Config::valueOf)
				.toArray(Config[]::new);
		return Config.create(flags);
	}

	/**
	 * Drops a handful of files into the share root so READ-dependent scenarios (e.g. {@code get}) have something to
	 * fetch even before the client performs any WRITE of its own.
	 */
	private static void seedFixtures() throws IOException {
		Files.writeString(shareRoot.resolve("greeting.txt"), """
				Hello from jSMB!
				This is a pre-seeded fixture for the READ scenario.
				""");
	}
}
