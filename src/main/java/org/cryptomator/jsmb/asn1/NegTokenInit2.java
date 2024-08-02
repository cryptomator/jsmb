package org.cryptomator.jsmb.asn1;

import java.nio.charset.StandardCharsets;

/**
 * A factory for NegTokenInit2 ASN.1 structures
 *
 * <pre>
 * NegotiationToken ::= CHOICE {
 *         negTokenInit    [0] NegTokenInit,
 *         negTokenResp    [1] NegTokenResp
 * }
 *
 * NegHints ::= SEQUENCE {
 *         hintName[0] GeneralString OPTIONAL,
 *         hintAddress[1] OCTET STRING OPTIONAL
 * }
 *
 * NegTokenInit2 ::= SEQUENCE {
 *         mechTypes[0] MechTypeList OPTIONAL,
 *         reqFlags [1] ContextFlags OPTIONAL,
 *         mechToken [2] OCTET STRING OPTIONAL,
 *         negHints [3] NegHints OPTIONAL,
 *         mechListMIC [4] OCTET STRING OPTIONAL,
 *         ...
 * }
 * </pre>
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-b5b5-38c92be3d472">NegTokenInit2 Syntax</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f5edf48c-57cc-4c61-bff9-ee19b9cd059e">NegTokenInit2 Example</a>
 */
public class NegTokenInit2 {

	private static final byte[] NOT_DEFINED_PLEASE_IGNORE = "not_defined_in_RFC4178@please_ignore".getBytes(StandardCharsets.US_ASCII);

	private NegTokenInit2() {
	}

	public static byte[] createNtlmOnly() {
		var negTokenInit2 = ASN1Node.constructed(ASN1Id.SEQUENCE,
				ASN1Node.constructed(ASN1Id.of(0xA0),
						ASN1Node.constructed(ASN1Id.SEQUENCE,
								ASN1Node.primitive(ASN1Id.OBJECT_IDENTIFIER, OID.NTLM) // MechType OID 1.3.6.1.4.1.311.2.2.10
						)
				),
				ASN1Node.constructed(ASN1Id.of(0xA3),
						ASN1Node.constructed(ASN1Id.SEQUENCE,
								ASN1Node.constructed(ASN1Id.of(0xA0),
										ASN1Node.primitive(ASN1Id.GENERAL_STRING, NOT_DEFINED_PLEASE_IGNORE)
								)
						)
				)
		);
		var negotiationToken = ASN1Node.constructed(ASN1Id.of(0xA0), negTokenInit2);
		// SPNEGO frame, as per RFC 4178, Section 4.2, only the first token shall be encapsulated in a SPNEGO frame:
		// "Subsequent tokens MUST NOT be encapsulated in this GSS-API generic token framing."
		var spnegoToken = ASN1Node.constructed(ASN1Id.APPLICATION,
				ASN1Node.primitive(ASN1Id.OBJECT_IDENTIFIER, OID.SPNEGO),
				negotiationToken
		);
		return spnegoToken.serialize();
	}

}