package org.cryptomator.jsmb.asn1;

import java.util.Arrays;

/**
 * <pre>
 * NegotiationToken ::= CHOICE {
 *         negTokenInit    [0] NegTokenInit,
 *         negTokenResp    [1] NegTokenResp
 * }
 *
 * NegTokenInit ::= SEQUENCE {
 * 	 mechTypes       [0] MechTypeList,
 * 	 reqFlags        [1] ContextFlags  OPTIONAL,
 * 	 -- inherited from RFC 2478 for backward compatibility,
 * 	 -- RECOMMENDED to be left out
 * 	 mechToken       [2] OCTET STRING  OPTIONAL,
 * 	 mechListMIC     [3] OCTET STRING  OPTIONAL,
 * 	 ...
 * }
 * </pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4178.html#section-4.2.1">RFC 4178 Section 4.2.1</a>
 */
public record NegTokenInit(ASN1Node.ASN1Constructed negTokenInit) implements NegotiationToken {

	private static final byte[] TAG_MECH_TYPES = ASN1Id.of(0xA0);
	private static final byte[] TAG_MECH_TOKEN = ASN1Id.of(0xA2);

	public static NegTokenInit parse(ASN1Node.ASN1Constructed negotiationToken) {
		var sequence = (ASN1Node.ASN1Constructed) negotiationToken.findChildWithId(ASN1Id.SEQUENCE);
		if (sequence == null) {
			throw new IllegalArgumentException("Expected sequence node");
		} else {
			return new NegTokenInit(sequence);
		}
	}

	public byte[][] getContentTypes() {
		var node = getMechTypesNode().findChildWithId(ASN1Id.SEQUENCE);
		if (node instanceof ASN1Node.ASN1Constructed sequence) {
			return sequence.children().stream()
					.filter(c -> c instanceof ASN1Node.ASN1Primitive p && Arrays.equals(ASN1Id.OBJECT_IDENTIFIER, p.identifier()))
					.map(c -> ((ASN1Node.ASN1Primitive) c).data())
					.toArray(byte[][]::new);
		} else {
			throw new IllegalArgumentException("Expected sequence node");
		}
	}

	private ASN1Node.ASN1Constructed getMechTypesNode() {
		var node = negTokenInit.findChildWithId(TAG_MECH_TYPES);
		if (node instanceof ASN1Node.ASN1Constructed c) {
			return c;
		} else {
			throw new IllegalArgumentException("Expected constructed node");
		}
	}

	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
	public byte[] getMechToken() {
		var node = getMechTokenNode().findChildWithId(ASN1Id.OCTET_STRING);
		if (node instanceof ASN1Node.ASN1Primitive p) {
			return p.data();
		} else {
			throw new IllegalArgumentException("Expected OCTET STRING node");
		}
	}

	private ASN1Node.ASN1Constructed getMechTokenNode() {
		var node = negTokenInit.findChildWithId(TAG_MECH_TOKEN);
		if (node instanceof ASN1Node.ASN1Constructed c) {
			return c;
		} else {
			throw new IllegalArgumentException("Expected constructed node");
		}
	}

}
