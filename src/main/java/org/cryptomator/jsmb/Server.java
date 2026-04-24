package org.cryptomator.jsmb;

import org.cryptomator.jsmb.share.SmbShare;
import org.cryptomator.jsmb.smb2.Global;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The entry point for embedders: bind a TCP port, register one or more {@link SmbShare shares}, and let
 * the server accept connections until {@link #close()} is called.
 */
public class Server implements AutoCloseable {

	private static final Logger LOG = LoggerFactory.getLogger(Server.class);

	private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
	private final ServerSocket serverSocket;
	private final Thread acceptor;
	/** Server GUID advertised in {@code NEGOTIATE} responses; freshly generated per instance. */
	public final UUID guid;
	/** Instant this server instance was constructed, reported as {@code ServerStartTime} in {@code NEGOTIATE}. */
	public final Instant startTime;
	/** Per-server global state (registered shares, config flags, credentials) shared across all connections. */
	public final Global global;

	private Server(ServerSocket serverSocket, Set<Config> config, Credentials credentials, ServerIdentity identity) {
		this.guid = UUID.randomUUID();
		this.startTime = Instant.now();
		this.serverSocket = serverSocket;
		this.acceptor = Thread.ofVirtual().name("TCP Connection Listener").uncaughtExceptionHandler(this::handleAcceptException).start(this::acceptConnections);
		this.global = new Global(config, credentials, identity);
	}

	public int getLocalPort() {
		return serverSocket.getLocalPort();
	}

	/**
	 * Registers {@code share} under {@code name} so that clients connecting via {@code TREE_CONNECT}
	 * to {@code \\host\<name>} are routed to it. May be called at any time, even after the server is
	 * running; new tree-connects see the updated set while already-open handles are unaffected.
	 *
	 * @param name  share name clients will connect to (case-insensitive on the wire)
	 * @param share backend serving the share
	 * @throws IllegalArgumentException if a share is already registered under {@code name}
	 */
	public void registerShare(String name, SmbShare share) {
		var existing = global.shares.putIfAbsent(name, share);
		if (existing != null) {
			throw new IllegalArgumentException("Share '" + name + "' is already registered");
		}
		LOG.debug("Registered share '{}'", name);
	}

	/**
	 * Starts a new server with {@link Config#DEFAULT}.
	 *
	 * @param port        TCP port to listen on, or {@code 0} to pick an ephemeral port
	 * @param credentials the single identity this server accepts; held for the server's lifetime
	 * @return a running server; close it to stop accepting new connections
	 * @throws IOException if the listening socket cannot be opened
	 */
	public static Server start(int port, Credentials credentials) throws IOException {
		return start(port, Config.DEFAULT, credentials);
	}

	/**
	 * Starts a new server with the supplied set of {@link Config} flags and the single {@link Credentials} pair it will
	 * accept for NTLMv2 session setup.
	 * <p>
	 * Callers typically build this set via {@link Config#create(Config...)}:
	 * <pre>{@code
	 * TcpServer.start(4445, Config.DEFAULT, new Credentials("DOMAIN", "user", "password"));
	 * }</pre>
	 *
	 * @param port        TCP port to listen on, or {@code 0} to pick an ephemeral port
	 * @param flags       set of enabled toggles; an absent flag is disabled
	 * @param credentials the single identity this server accepts; held for the server's lifetime
	 * @return a running server; close it to stop accepting new connections
	 * @throws IOException if the listening socket cannot be opened
	 */
	public static Server start(int port, Set<Config> flags, Credentials credentials) throws IOException {
		return start(port, flags, credentials, ServerIdentity.DEFAULT);
	}

	/**
	 * As {@link #start(int, Set, Credentials)}, but with an explicit {@link ServerIdentity} — override it to announce a
	 * specific NetBIOS / DNS computer + domain name in the NTLMv2 {@code CHALLENGE_MESSAGE}. The default
	 * ({@link ServerIdentity#DEFAULT}) mirrors jSMB's historical hardcoded values.
	 *
	 * @param port        TCP port to listen on, or {@code 0} to pick an ephemeral port
	 * @param flags       set of enabled toggles; an absent flag is disabled
	 * @param credentials the single identity this server accepts; held for the server's lifetime
	 * @param identity    how this server names itself to NTLMv2 clients
	 * @return a running server; close it to stop accepting new connections
	 * @throws IOException if the listening socket cannot be opened
	 */
	public static Server start(int port, Set<Config> flags, Credentials credentials, ServerIdentity identity) throws IOException {
		var serverSocket = new ServerSocket(port);
		LOG.info("Server started on port {}", serverSocket.getLocalPort());
		return new Server(serverSocket, flags, credentials, identity);
	}

	private void acceptConnections() {
		try {
			while (!Thread.interrupted()) {
				var clientSocket = serverSocket.accept();
				executor.execute(new TcpConnection(this, clientSocket));
			}
		} catch (IOException e) {
			if (Thread.interrupted()) {
				LOG.debug("Listener interrupted, shutting down");
				return;
			}
			throw new UncheckedIOException(e);
		} finally {
			executor.shutdown();
		}
	}

	private void handleAcceptException(Thread thread, Throwable throwable) {
		LOG.error("Uncaught exception in thread '{}'", thread.getName(), throwable);
	}

	@Override
	public void close() throws IOException {
		acceptor.interrupt();
		executor.close();
		serverSocket.close();
	}
}
