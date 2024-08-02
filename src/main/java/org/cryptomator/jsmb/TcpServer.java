package org.cryptomator.jsmb;

import org.cryptomator.jsmb.smb2.Global;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.time.Instant;
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

	private TcpServer(ServerSocket serverSocket) {
		this.guid = UUID.randomUUID();
		this.startTime = Instant.now();
		this.serverSocket = serverSocket;
		this.acceptor = Thread.ofVirtual().name("TCP Connection Listener").uncaughtExceptionHandler(this::handleAcceptException).start(this::acceptConnections);
		this.global = new Global();
	}

	public int getLocalPort() {
		return serverSocket.getLocalPort();
	}

	public static TcpServer start(int port) throws IOException {
		var serverSocket = new ServerSocket(port);
		LOG.info("Server started on port {}", serverSocket.getLocalPort());
		return new TcpServer(serverSocket);
	}

	private void acceptConnections() {
		try {
			while (!Thread.interrupted()) {
				var clientSocket = serverSocket.accept();
				executor.execute(new TcpConnection(this, clientSocket));
			}
		} catch (IOException e) {
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
