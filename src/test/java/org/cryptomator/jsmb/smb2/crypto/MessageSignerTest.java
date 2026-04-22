package org.cryptomator.jsmb.smb2.crypto;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.PacketHeaderBuilder;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.smb2.SessionSetupResponse;
import org.cryptomator.jsmb.smb2.negotiate.SigningCapabilities;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Base64;
import java.util.HexFormat;

class MessageSignerTest {

	private final static HexFormat HEX_FORMAT = HexFormat.of();

	@Test
	@DisplayName("AES-GMAC matches the NIST CAVP test vector")
	public void testGmacSignature() {
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

	@Test
	@DisplayName("AES-CMAC matches the NIST SP 800-38B example vector")
	public void testCMAC() {
		// test vector from NIST Cryptographic Standards and Guidelines: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values (https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf)
		/*
		Key = 2B7E1516 28AED2A6 ABF71588 09CF4F3C
		PT = 6BC1BEE2 2E409F96 E93D7E11 7393172A
		Last Block > Block #1 > outBlock = 070A16B4 6B4D4144 F79BDD9D D04A287C
		 */
		var data = HEX_FORMAT.parseHex("6bc1bee22e409f96e93d7e117393172a");
		var signer = new MessageSigner();

		var signature = signer.cmac(data, HEX_FORMAT.parseHex("2b7e151628aed2a6abf7158809cf4f3c"));

		Assertions.assertEquals("070a16b46b4d4144f79bdd9dd04a287c", HEX_FORMAT.formatHex(signature));
	}

	@ParameterizedTest
	@DisplayName("Signing a SESSION_SETUP response produces the expected signed bytes for each algorithm")
	@CsvSource(textBlock = """
			0x00000000ef9270f6,\
			fe534d42400001000000000001000020110000000000000002000000000000000000000000000000f67092ef0000000000000000000000000000000000000000,\
			a11b3019a0030a0100a3120410010000003336c415d6ca63b600000000,\
			fe534d42400001000000000001000020110000000000000002000000000000000000000000000000f67092ef00000000000000000000000000000000000000000900000048001d00a11b3019a0030a0100a3120410010000003336c415d6ca63b600000000,\
			23A69FFF57BCB19502BB74E79CE760DB,\
			AES_CMAC,\
			fe534d42400001000000000001000020190000000000000002000000000000000000000000000000f67092ef000000000df13f46f7f59874e581dbbe82736c040900000048001d00a11b3019a0030a0100a3120410010000003336c415d6ca63b600000000\
			
			0x00000000dfc1a81a,\
			fe534d424000010000000000010000201100000000000000020000000000000000000000000000001aa8c1df0000000000000000000000000000000000000000,\
			a11b3019a0030a0100a3120410010000009ddb82364613ea5600000000,\
			fe534d424000010000000000010000201100000000000000020000000000000000000000000000001aa8c1df00000000000000000000000000000000000000000900000048001d00a11b3019a0030a0100a3120410010000009ddb82364613ea5600000000,\
			E07AA62CC914810061E07EE1084FCE1B,\
			AES_GMAC,\
			fe534d424000010000000000010000201900000000000000020000000000000000000000000000001aa8c1df000000003484d3eef43af37ac480d6a4e2ee71400900000048001d00a11b3019a0030a0100a3120410010000009ddb82364613ea5600000000\
			""" //
	)
	public void testSigning(long sessionId, String expUnsignedHdrHex, String securityBufferHex, String expUnsignedMsgHex, String signingKeyHex, SigningCapabilities.Algorithm signingAlg, String expSignedMsgHex) {
		var unsignedHdr = new PacketHeaderBuilder() //
				.creditCharge((char) 1) //
				.status(NTStatus.STATUS_SUCCESS) //
				.command(Command.SESSION_SETUP.value()) //
				.creditResponse((char) 8192) //
				.flags(SMB2Message.Flags.withPriority(SMB2Message.Flags.SERVER_TO_REDIR, 1)) //
				.messageId(2) //
				.sessionId(sessionId) //
				.build();
		var expUnsignedHdr = HEX_FORMAT.parseHex(expUnsignedHdrHex);
		assertBytesEquals(expUnsignedHdr, unsignedHdr.segment().toArray(ValueLayout.OfByte.JAVA_BYTE));

		var unsignedMsg = new SessionSetupResponse(unsignedHdr).withSecurityBuffer(HEX_FORMAT.parseHex(securityBufferHex));
		var expUnsignedMsg = HEX_FORMAT.parseHex(expUnsignedMsgHex);
		assertBytesEquals(expUnsignedMsg, unsignedMsg.serialize());

		var signer = new MessageSigner();
		var signedMsg = new SignedMessage(signer.sign(unsignedMsg, HEX_FORMAT.parseHex(signingKeyHex), signingAlg), unsignedMsg.segment());
		var expSignedMsg = HEX_FORMAT.parseHex(expSignedMsgHex);
		assertBytesEquals(signedMsg.serialize(), expSignedMsg);
	}

	record SignedMessage(PacketHeader header, MemorySegment segment) implements SMB2Message {

	}

	private void assertBytesEquals(byte[] expected, byte[] actual) {
		Assertions.assertEquals(HEX_FORMAT.formatHex(expected), HEX_FORMAT.formatHex(actual));
	}
}