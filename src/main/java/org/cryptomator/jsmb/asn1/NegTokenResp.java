package org.cryptomator.jsmb.asn1;

import java.util.HexFormat;

/**
 * <pre>
 * NegotiationToken ::= CHOICE {
 *     negTokenInit    [0] NegTokenInit,
 *     negTokenResp    [1] NegTokenResp
 * }
 *
 * NegTokenResp ::= SEQUENCE {
 *     negState       [0] ENUMERATED {
 *         accept-completed    (0),
 *         accept-incomplete   (1),
 *         reject              (2),
 *         request-mic         (3)
 *     }                                 OPTIONAL,
 *       -- REQUIRED in the first reply from the target
 *     supportedMech   [1] MechType      OPTIONAL,
 *       -- present only in the first reply from the target
 *     responseToken   [2] OCTET STRING  OPTIONAL,
 *     mechListMIC     [3] OCTET STRING  OPTIONAL,
 *     ...
 * }
 * </pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4178.html#section-4.2.2">RFC 4178 Section 4.2.2</a>
 */
public record NegTokenResp(ASN1Node.ASN1Constructed negTokenResp) implements NegotiationToken {

	private static final byte[] TAG_NEG_STATE = ASN1Id.of(0xA0);
	private static final byte[] TAG_RESPONSE_TOKEN = ASN1Id.of(0xA2);

	public static NegTokenResp parse(ASN1Node.ASN1Constructed negotiationToken) {
		var sequence = (ASN1Node.ASN1Constructed) negotiationToken.findChildWithId(ASN1Id.SEQUENCE);
		if (sequence == null) {
			throw new IllegalArgumentException("Expected sequence node");
		} else {
			return new NegTokenResp(sequence);
		}
	}

	public int getNegState() {
		var node = getNegStateNode().findChildWithId(ASN1Id.ENUMERATED);
		if (node instanceof ASN1Node.ASN1Primitive p) {
			return p.data()[0];
		} else {
			throw new IllegalArgumentException("Expected enumerated value");
		}
	}

	private ASN1Node.ASN1Constructed getNegStateNode() {
		var node = negTokenResp.findChildWithId(TAG_NEG_STATE);
		if (node instanceof ASN1Node.ASN1Constructed c) {
			return c;
		} else {
			throw new IllegalArgumentException("Expected node with tag " + HexFormat.of().formatHex(TAG_NEG_STATE));
		}
	}

	@Override
	public byte[] token() {
		return getResponseToken();
	}

	public byte[] getResponseToken() {
		var node = getResponseTokenNode().findChildWithId(ASN1Id.OCTET_STRING);
		if (node instanceof ASN1Node.ASN1Primitive p) {
			return p.data();
		} else {
			throw new IllegalArgumentException("Expected octet string");
		}
	}

	private ASN1Node.ASN1Constructed getResponseTokenNode() {
		var node = negTokenResp.findChildWithId(TAG_RESPONSE_TOKEN);
		if (node instanceof ASN1Node.ASN1Constructed c) {
			return c;
		} else {
			throw new IllegalArgumentException("Expected node with tag " + HexFormat.of().formatHex(TAG_RESPONSE_TOKEN));
		}
	}

	/**
	 * Creates a GSS negotation token response with state <pre>accept-incomplete</pre>
	 * @param responseToken the mechanism-specific response token (in case of this project the NTLM server challenge)
	 * @return a NegTokenResp structure
	 */
	public static NegTokenResp acceptIncomplete(byte[] responseToken) {
		var negTokenResp = ASN1Node.constructed(ASN1Id.SEQUENCE,
				ASN1Node.constructed(ASN1Id.of(0xA0),
						ASN1Node.primitive(ASN1Id.ENUMERATED, new byte[]{0x01}) // negState ENUMERATED accept-incomplete
				),
				ASN1Node.constructed(ASN1Id.of(0xA1),
						ASN1Node.primitive(ASN1Id.OBJECT_IDENTIFIER, OID.NTLM)
				),
				ASN1Node.constructed(ASN1Id.of(0xA2),
						ASN1Node.primitive(ASN1Id.OCTET_STRING, responseToken)
				)
		);
		var negotiationToken = ASN1Node.constructed(ASN1Id.of(0xA1), negTokenResp);
		return new NegTokenResp(negotiationToken);
	}

}
