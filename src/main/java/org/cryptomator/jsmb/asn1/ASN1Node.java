package org.cryptomator.jsmb.asn1;

import org.cryptomator.jsmb.util.Bytes;

import java.util.List;

sealed interface ASN1Node permits ASN1Node.ASN1Primitive, ASN1Node.ASN1Constructed {

	byte[] identifier();

	byte[] data();

	List<ASN1Node> children();

	default boolean isPrimitive() {
		return children().isEmpty();
	}

	default byte[] serialize() {
		var data = isPrimitive() ? data() : children().stream().map(ASN1Node::serialize).reduce(new byte[0], Bytes::concat);
		var length = toAsn1Length(data.length);
		return Bytes.concat(identifier(), length, data);
	}

	private static byte[] toAsn1Length(int length) {
		if (length < 0x80) {
			return new byte[] { (byte) length };
		} else if (length < 0x100) {
			return new byte[] { (byte) 0x81, (byte) length };
		} else if (length < 0x10000) {
			return new byte[] { (byte) 0x82, (byte) (length >> 8), (byte) length };
		} else if (length < 0x1000000) {
			return new byte[] { (byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length };
		} else {
			return new byte[] { (byte) 0x84, (byte) (length >> 24), (byte) (length >> 16), (byte) (length >> 8), (byte) length };
		}
	}

	static ASN1Node primitive(byte[] identifier, byte[] data) {
		return new ASN1Primitive(identifier, data);
	}

	static ASN1Node constructed(byte[] identifier, ASN1Node... children) {
		return new ASN1Constructed(identifier, List.of(children));
	}

	record ASN1Primitive(byte[] identifier, byte[] data) implements ASN1Node {
		@Override
		public List<ASN1Node> children() {
			return List.of();
		}
	}

	record ASN1Constructed(byte[] identifier, List<ASN1Node> children) implements ASN1Node {
		@Override
		public byte[] data() {
			return new byte[0];
		}
	}
}
