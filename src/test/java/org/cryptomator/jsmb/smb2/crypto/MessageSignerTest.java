package org.cryptomator.jsmb.smb2.crypto;

import org.cryptomator.jsmb.smb2.Session;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.ByteBuffer;
import java.util.Base64;

class MessageSignerTest {

	@Test
	public void testGmacSignature() {
		var data = Base64.getDecoder().decode("/lNNQkAAAAAAAAAAAQAAIAEAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAABIAAkAoQcwBaADCgEA");
		var nonce = new byte[12];
		ByteBuffer.wrap(nonce) //
				.putLong(0, 2L) //
				.putInt(8, 1);
		var session = Mockito.mock(Session.class);
		var signer = new MessageSigner(session);

		var signature = signer.gmac(data, nonce, Base64.getDecoder().decode("9fORJ+Vx1QUv43YChZvR6A=="));

		Assertions.assertEquals("5W28PWtNfcE+BVqzLOsDdg==", Base64.getEncoder().encodeToString(signature));
	}

}