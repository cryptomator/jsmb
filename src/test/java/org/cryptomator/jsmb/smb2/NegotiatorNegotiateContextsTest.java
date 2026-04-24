package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.Server;
import org.cryptomator.jsmb.smb2.negotiate.CompressionCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.EncryptionCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.NegotiateContext;
import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.RDMATransformCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.SigningCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.TransportCapabilities;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Regression guard for MS-SMB2 §3.3.5.4 negotiate-context gating. When the client offers contexts
 * for features the server does not support ({@code IsCompressionSupported = FALSE},
 * {@code IsRDMATransformSupported = FALSE}, {@code IsTransportCapabilitiesSupported = FALSE}), the
 * spec says "the server MUST ignore the [request] context" — and consequently must not emit a
 * matching response context. Windows clients enforce this and abort the handshake when the server
 * emits an {@code ALG_NONE} / {@code TRANSFORM_NONE} stub (see {@code jsmb_windows_port_test} capture).
 */
class NegotiatorNegotiateContextsTest {

	private Server server;
	private Negotiator negotiator;

	@BeforeEach
	void setUp() throws IOException {
		server = Server.start(0, Config.create(), new Credentials("DOMAIN", "user", "password"));
		var connection = new Connection(server.global);
		negotiator = new Negotiator(server, connection);
	}

	@AfterEach
	void tearDown() throws IOException {
		if (server != null) server.close();
	}

	@Test
	@DisplayName("NEGOTIATE response includes only contexts for features we support — compression / RDMA / transport are dropped")
	void omitsUnsupportedContexts() {
		// Client sends all six 3.1.1 negotiate contexts.
		var contexts = List.of(
				PreauthIntegrityCapabilities.build(PreauthIntegrityCapabilities.HASH_ALGORITHM_SHA512, new byte[32]),
				EncryptionCapabilities.build(EncryptionCapabilities.AES_128_GCM),
				CompressionCapabilities.build(new char[]{CompressionCapabilities.ALG_LZ77}, CompressionCapabilities.FLAG_NONE),
				SigningCapabilities.build(SigningCapabilities.Algorithm.AES_CMAC.getValue()),
				RDMATransformCapabilities.build(new char[]{RDMATransformCapabilities.TRANSFORM_NONE}),
				TransportCapabilities.build(0));
		var request = buildNegotiateRequest(contexts);

		var response = negotiator.negotiate(request);

		Assertions.assertInstanceOf(NegotiateResponse.class, response);
		var responseContextTypes = extractContextTypes((NegotiateResponse) response);

		// Preauth is spec-mandated; Encryption + Signing are echoed because our server supports them.
		Assertions.assertTrue(responseContextTypes.contains(NegotiateContext.PREAUTH_INTEGRITY_CAPABILITIES),
				"PREAUTH_INTEGRITY_CAPABILITIES is mandatory for 3.1.1");
		Assertions.assertTrue(responseContextTypes.contains(NegotiateContext.ENCRYPTION_CAPABILITIES),
				"ENCRYPTION_CAPABILITIES must be echoed when the client offered it (we support encryption)");
		Assertions.assertTrue(responseContextTypes.contains(NegotiateContext.SIGNING_CAPABILITIES),
				"SIGNING_CAPABILITIES must be echoed when the client offered it (we support signing)");

		// These three: server must NOT emit them (the IsXxxSupported flags are FALSE).
		Assertions.assertFalse(responseContextTypes.contains(NegotiateContext.COMPRESSION_CAPABILITIES),
				"COMPRESSION_CAPABILITIES must be dropped — IsCompressionSupported is FALSE");
		Assertions.assertFalse(responseContextTypes.contains(NegotiateContext.RDMA_TRANSFORM_CAPABILITIES),
				"RDMA_TRANSFORM_CAPABILITIES must be dropped — IsRDMATransformSupported is FALSE");
		Assertions.assertFalse(responseContextTypes.contains(NegotiateContext.TRANSPORT_CAPABILITIES),
				"TRANSPORT_CAPABILITIES must be dropped — IsTransportCapabilitiesSupported is FALSE");

		// And the count on the wire must match.
		Assertions.assertEquals(3, responseContextTypes.size(),
				"expected exactly 3 contexts in the response (Preauth, Encryption, Signing); got " + responseContextTypes);
	}

	/** Pulls the {@code ContextType} of every negotiate context from a NegotiateResponse. */
	private static Set<Character> extractContextTypes(NegotiateResponse response) {
		int count = response.segment().get(Layouts.LE_UINT16, 6);
		int contextsBodyOffset = response.segment().get(Layouts.LE_INT32, 60) - PacketHeader.STRUCTURE_SIZE;
		var types = new HashSet<Character>();
		for (int i = 0, pos = contextsBodyOffset; i < count; i++) {
			if (pos % 8 != 0) pos += (8 - pos % 8) % 8;
			char contextType = response.segment().get(Layouts.LE_UINT16, pos);
			char dataLength = response.segment().get(Layouts.LE_UINT16, pos + 2);
			types.add(contextType);
			pos += 8 + dataLength;
		}
		return types;
	}

	/**
	 * Builds a minimal but well-formed SMB2 NEGOTIATE request body carrying one dialect (3.1.1) and
	 * the supplied negotiate contexts, 8-byte-aligned per MS-SMB2 2.2.3.
	 */
	private static NegotiateRequest buildNegotiateRequest(List<NegotiateContext> contexts) {
		int fixed = 36; // StructureSize .. Reserved2
		int dialectBytes = 2;
		int paddingAfterDialects = (8 - (fixed + dialectBytes) % 8) % 8;
		int contextsStart = fixed + dialectBytes + paddingAfterDialects;

		int contextsTotal = 0;
		for (int i = 0; i < contexts.size(); i++) {
			var ctx = contexts.get(i);
			contextsTotal += ctx.segmentSize();
			if (i < contexts.size() - 1) {
				contextsTotal += (8 - ctx.segmentSize() % 8) % 8; // inter-context padding
			}
		}

		var body = MemorySegment.ofArray(new byte[contextsStart + contextsTotal]);
		body.set(Layouts.LE_UINT16, 0, (char) 36);              // StructureSize
		body.set(Layouts.LE_UINT16, 2, (char) 1);               // DialectCount
		body.set(Layouts.LE_UINT16, 4, (char) 0);               // SecurityMode
		body.set(Layouts.LE_UINT16, 6, (char) 0);               // Reserved
		body.set(Layouts.LE_INT32, 8, 0);                       // Capabilities
		// ClientGuid @ 12..27 — zero
		body.set(Layouts.LE_INT32, 28, PacketHeader.STRUCTURE_SIZE + contextsStart); // NegotiateContextOffset
		body.set(Layouts.LE_UINT16, 32, (char) contexts.size()); // NegotiateContextCount
		body.set(Layouts.LE_UINT16, 34, (char) 0);              // Reserved2
		body.set(Layouts.LE_UINT16, 36, Dialects.SMB3_1_1);

		int pos = contextsStart;
		for (int i = 0; i < contexts.size(); i++) {
			var ctxSeg = contexts.get(i).segment();
			MemorySegment.copy(ctxSeg, 0, body, pos, ctxSeg.byteSize());
			pos += (int) ctxSeg.byteSize();
			if (i < contexts.size() - 1 && pos % 8 != 0) {
				pos += (8 - pos % 8) % 8;
			}
		}

		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, SMB2Message.PROTOCOL_ID);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.NEGOTIATE.value());
		return new NegotiateRequest(new PacketHeader(headerSeg), body);
	}
}
