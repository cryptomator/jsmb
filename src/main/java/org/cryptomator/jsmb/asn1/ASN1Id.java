package org.cryptomator.jsmb.asn1;

interface ASN1Id {

	// constructed
	byte[] APPLICATION = new byte[] { 0x60 };
	byte[] SEQUENCE = new byte[] { 0x30 };

	// primitive
	byte[] OCTET_STRING = new byte[] { 0x04 };
	byte[] OBJECT_IDENTIFIER = new byte[] { 0x06 };
	byte[] GENERAL_STRING = new byte[] { 0x1B };

	static byte[] of(int... bytes) {
		byte[] result = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			result[i] = (byte) bytes[i];
		}
		return result;
	}

}
