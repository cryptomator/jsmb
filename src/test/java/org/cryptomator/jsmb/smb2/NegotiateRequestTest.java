package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.foreign.MemorySegment;

class NegotiateRequestTest {

	@ParameterizedTest(name = "{0} dialects")
	@DisplayName("Negotiate contexts are found at NegotiateContextOffset, however many dialects precede them")
	@ValueSource(ints = {1, 2, 3, 4, 5, 6})
	void negotiateContextsAtOffset(int dialectCount) {
		var context = PreauthIntegrityCapabilities.build(PreauthIntegrityCapabilities.HASH_ALGORITHM_SHA512, new byte[32]).segment();
		int endOfDialects = 36 + dialectCount * Character.BYTES;
		int contextsStart = (endOfDialects + 7) / 8 * 8; // 8-byte aligned, which holds for the whole message as well, as the header takes 64 bytes
		var body = MemorySegment.ofArray(new byte[(int) (contextsStart + context.byteSize())]);
		body.set(Layouts.LE_UINT16, 0, (char) 36); // StructureSize
		body.set(Layouts.LE_UINT16, 2, (char) dialectCount);
		body.set(Layouts.LE_INT32, 28, PacketHeader.STRUCTURE_SIZE + contextsStart); // NegotiateContextOffset
		body.set(Layouts.LE_UINT16, 32, (char) 1); // NegotiateContextCount
		for (int i = 0; i < dialectCount; i++) {
			body.set(Layouts.LE_UINT16, 36 + i * Character.BYTES, i == 0 ? Dialects.SMB3_1_1 : Dialects.SMB3_0);
		}
		MemorySegment.copy(context, 0, body, contextsStart, context.byteSize());
		var request = new NegotiateRequest(PacketHeader.builder().command(Command.NEGOTIATE.value()).build(), body);

		var preauthIntegrityCapabilities = request.negotiateContext(PreauthIntegrityCapabilities.class);

		Assertions.assertNotNull(preauthIntegrityCapabilities);
	}
}
