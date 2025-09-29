package org.cryptomator.jsmb.smb2.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
		var signer = new MessageSigner();

		var signature = signer.gmac(data, nonce, Base64.getDecoder().decode("9fORJ+Vx1QUv43YChZvR6A=="));

		Assertions.assertEquals("5W28PWtNfcE+BVqzLOsDdg==", Base64.getEncoder().encodeToString(signature));
	}

	@Test
	public void testGmacSignature2() {
		// test vector from NIST CAVP: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
		/*
		Key = a4851117328a93bf528382f22f35ac94688259fd2f517e4fd27ee9cf9b8c8a2c
		IV = 44395ca4943aca24875a281a
		CT =
		AAD = b9a63c85bd7cb93c9d2543572099ac0a0b1ab4dddbea4c75bacfab9755ae763cb1062a594dda9ca860134c74776752ad357cfda32d1c20e896370dac5808c147061ed1545a2a6ff26fe2e0e2e38ec887c1e210cecad4a8c9a86d
		Tag = 1b13e6132415fd70d9092e32ff2759be
		 */
		var data = Base64.getDecoder().decode("uaY8hb18uTydJUNXIJmsCgsatN3b6kx1us+rl1WudjyxBipZTdqcqGATTHR3Z1KtNXz9oy0cIOiWNw2sWAjBRwYe0VRaKm/yb+Lg4uOOyIfB4hDOytSoyaht");
		var nonce = Base64.getDecoder().decode("RDlcpJQ6yiSHWiga");
		var signer = new MessageSigner();

		var signature = signer.gmac(data, nonce, Base64.getDecoder().decode("pIURFzKKk79Sg4LyLzWslGiCWf0vUX5P0n7pz5uMiiw="));

		Assertions.assertEquals("GxPmEyQV/XDZCS4y/ydZvg==", Base64.getEncoder().encodeToString(signature));

	}

}