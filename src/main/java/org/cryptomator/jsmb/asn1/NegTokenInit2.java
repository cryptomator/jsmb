package org.cryptomator.jsmb.asn1;

import java.nio.charset.StandardCharsets;

/**
 * A factory for NegTokenInit2 ASN.1 structures
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-b5b5-38c92be3d472">NegTokenInit2 Syntax</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f5edf48c-57cc-4c61-bff9-ee19b9cd059e">NegTokenInit2 Example</a>
 */
public class NegTokenInit2 {

	private NegTokenInit2() {
	}

	public static byte[] createNtlmOnly() {
		var rootNode = ASN1Node.constructed(ASN1Id.APPLICATION,
				ASN1Node.primitive(ASN1Id.OBJECT_IDENTIFIER, new byte[]{0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}), // OID 1.3.6.1.5.5.2
				ASN1Node.constructed(ASN1Id.of(0xA0),
						ASN1Node.constructed(ASN1Id.SEQUENCE,
								ASN1Node.constructed(ASN1Id.of(0xA0),
										ASN1Node.constructed(ASN1Id.SEQUENCE,
												ASN1Node.primitive(ASN1Id.OBJECT_IDENTIFIER, new byte[]{0x2B, 0x06, 0x01, 0x04, 0x01, (byte) 0x82, 0x37, 0x02, 0x02, 0x0A}) // MechType OID 1.3.6.1.4.1.311.2.2.10
										)
								),
//								ASN1Node.constructed(ASN1Id.of(0xA2),
//										ASN1Node.primitive(ASN1Id.OCTET_STRING, mechToken)
//								),
								ASN1Node.constructed(ASN1Id.of(0xA3),
										ASN1Node.constructed(ASN1Id.SEQUENCE,
												ASN1Node.constructed(ASN1Id.of(0xA0),
														ASN1Node.primitive(ASN1Id.GENERAL_STRING, "not_defined_in_RFC4178@please_ignore".getBytes(StandardCharsets.US_ASCII))
												)
										)
								)
						)
				)
		);
		return rootNode.serialize();
	}

}