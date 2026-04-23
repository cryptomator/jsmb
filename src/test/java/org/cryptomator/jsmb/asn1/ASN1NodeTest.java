package org.cryptomator.jsmb.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Base64;

class ASN1NodeTest {

	@Test
	@DisplayName("Parsing and re-serializing an ASN.1 node reproduces the original bytes")
	public void parseAndSerialize() {
		// see also https://lapo.it/asn1js/#YH4GBisGAQUFAqB0MHKgRDBCBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYGKoVwKw4DBgYrBgEFBQ4GCisGAQQBgjcCAgoGBisFAQUCBwYGKwYBBQIFoyowKKAmGyRub3RfZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU
		byte[] original = Base64.getDecoder().decode("YH4GBisGAQUFAqB0MHKgRDBCBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYGKoVwKw4DBgYrBgEFBQ4GCisGAQQBgjcCAgoGBisFAQUCBwYGKwYBBQIFoyowKKAmGyRub3RfZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU=");
		var parsed = ASN1Node.parse(ByteBuffer.wrap(original));
		var serialized = parsed.serialize();
		Assertions.assertArrayEquals(original, serialized);
	}

	@Test
	@DisplayName("A blob whose declared length exceeds the buffer surfaces as IllegalArgumentException")
	public void overLongDeclaredLengthIsRejected() {
		// Tag 0x30 (SEQUENCE, constructed) with a declared length of 84 bytes but only 2 bytes of content.
		// Before the bounds check this used to throw IndexOutOfBoundsException from ByteBuffer.get,
		// killing the connection-handling thread.
		byte[] malformed = {0x30, 0x54, 0x01, 0x02};

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> ASN1Node.parse(ByteBuffer.wrap(malformed)));
	}

}