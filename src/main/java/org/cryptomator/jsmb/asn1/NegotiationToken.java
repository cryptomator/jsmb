package org.cryptomator.jsmb.asn1;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * A token used in the negotiation of security parameters.
 * <pre>
 * NegotiationToken ::= CHOICE {
 *         negTokenInit    [0] NegTokenInit,
 *         negTokenResp    [1] NegTokenResp
 * }
 * </pre>
 */
public sealed interface NegotiationToken permits NegTokenInit, NegTokenResp {

	byte[] NEG_TOKEN_INIT_TAG = {(byte) 0xA0};
	byte[] NEG_TOKEN_RESP_TAG = {(byte) 0xA1};

	/**
	 * The mechanism-specific token.
	 * <p>
	 * In case of NTLM, {@link NegTokenInit#getMechToken()} is expected to hold a NEGOTIATE_MESSAGE,
	 * while {@link NegTokenResp#getResponseToken()} holds a CHALLENGE_MESSAGE or an AUTHENTICATE_MESSAGE.
	 * @return The mechanism-specific token
	 */
	byte[] token();

	static NegotiationToken parse(byte[] token) {
		ASN1Node node = ASN1Node.parse(ByteBuffer.wrap(token));
		if (node instanceof ASN1Node.ASN1Constructed constructed) {
			return parse(constructed);
		} else {
			throw new IllegalArgumentException("Expected constructed node " + HexFormat.of().formatHex(token));
		}
	}

	private static NegotiationToken parse(ASN1Node.ASN1Constructed node) {
		var innerNode = stripSpnegoHeader(node);
		if (!(innerNode instanceof ASN1Node.ASN1Constructed negToken)) {
			throw new IllegalArgumentException("Expected SPNEGO token, got " + node);
		}
		if (Arrays.equals(NEG_TOKEN_INIT_TAG, negToken.identifier())) {
			return NegTokenInit.parse(negToken);
		} else if (Arrays.equals(NEG_TOKEN_RESP_TAG, negToken.identifier())) {
			return NegTokenResp.parse(negToken);
		} else {
			throw new IllegalArgumentException("Expected SPNEGO token, got " + node);
		}
	}

	/**
	 * Extracts the inner context token from a SPNEGO token.
	 * @param node The outer SPNEGO token
	 * @return The inner context token, if the outer token is in fact a SPNEGO token
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2743#page-83">RFC 2743, Page 83</a>
	 */
	private static ASN1Node stripSpnegoHeader(ASN1Node.ASN1Constructed node) {
		if (Arrays.equals(ASN1Id.APPLICATION, node.identifier())) {
			var oidNode = node.childAtIndex(0);
			if (Arrays.equals(ASN1Id.OBJECT_IDENTIFIER, oidNode.identifier()) && oidNode instanceof ASN1Node.ASN1Primitive oid && Arrays.equals(OID.SPNEGO, oid.data())) {
				return node.childAtIndex(1);
			}
		}
		return node; // fallback: leave original node unchanged
	}
}
