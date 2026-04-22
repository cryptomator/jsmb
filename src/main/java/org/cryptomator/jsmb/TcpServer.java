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

public class TcpServer implements AutoCloseable {

	private static final Logger LOG = LoggerFactory.getLogger(TcpServer.class);

	private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
	private final ServerSocket serverSocket;
	private final Thread acceptor;
	public final UUID guid;
	public final Instant startTime;
	public final Global global;

	private TcpServer(ServerSocket serverSocket, Set<Config> config) {
		this.guid = UUID.randomUUID();
		this.startTime = Instant.now();
		this.serverSocket = serverSocket;
		this.acceptor = Thread.ofVirtual().name("TCP Connection Listener").uncaughtExceptionHandler(this::handleAcceptException).start(this::acceptConnections);
		this.global = new Global(config);
	}

	public int getLocalPort() {
		return serverSocket.getLocalPort();
	}

	/**
	 * Registers {@code share} under {@code name} so that clients connecting via {@code TREE_CONNECT}
	 * to {@code \\host\<name>} are routed to it. May be called at any time, even after the server is
	 * running; new tree-connects see the updated set while already-open handles are unaffected.
	 *
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
	 */
	public static TcpServer start(int port) throws IOException {
		return start(port, Config.DEFAULT);
	}

	/**
	 * Starts a new server with the supplied set of {@link Config} flags.
	 * <p>
	 * Callers typically build this set via {@link Config#create(Config...)}:
	 * <pre>{@code
	 * TcpServer.start(4445, Config.DEFAULT);
	 * }</pre>
	 *
	 * @param port  TCP port to listen on, or {@code 0} to pick an ephemeral port
	 * @param flags set of enabled toggles; an absent flag is disabled
	 */
	public static TcpServer start(int port, Set<Config> flags) throws IOException {
		var serverSocket = new ServerSocket(port);
		LOG.info("Server started on port {}", serverSocket.getLocalPort());
		return new TcpServer(serverSocket, flags);
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
