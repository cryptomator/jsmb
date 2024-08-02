package org.cryptomator.jsmb.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Base64;

class ASN1NodeTest {

	@Test
	public void parseAndSerialize() {
		// see also https://lapo.it/asn1js/#YH4GBisGAQUFAqB0MHKgRDBCBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYGKoVwKw4DBgYrBgEFBQ4GCisGAQQBgjcCAgoGBisFAQUCBwYGKwYBBQIFoyowKKAmGyRub3RfZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU
		byte[] original = Base64.getDecoder().decode("YH4GBisGAQUFAqB0MHKgRDBCBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYGKoVwKw4DBgYrBgEFBQ4GCisGAQQBgjcCAgoGBisFAQUCBwYGKwYBBQIFoyowKKAmGyRub3RfZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU=");
		var parsed = ASN1Node.parse(ByteBuffer.wrap(original));
		var serialized = parsed.serialize();
		Assertions.assertArrayEquals(original, serialized);
	}

}