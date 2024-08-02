package org.cryptomator.jsmb.asn1;

import org.cryptomator.jsmb.util.Bytes;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @see <a href="https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf">ITU-T X.690</a>
 */
public sealed interface ASN1Node permits ASN1Node.ASN1Primitive, ASN1Node.ASN1Constructed {

	byte[] identifier();

	byte[] length();

	default int size() {
		var headerSize = identifier().length + length().length;
		var bodySize = switch (this) {
			case ASN1Primitive p -> p.data().length;
			case ASN1Constructed c -> c.children().stream().mapToInt(ASN1Node::size).sum();
		};
		return headerSize + bodySize;
	}

	default byte[] serialize() {
		var data = switch (this) {
			case ASN1Primitive p -> p.data();
			case ASN1Constructed c -> c.children().stream().map(ASN1Node::serialize).reduce(new byte[0], Bytes::concat);
		};
		var length = toAsn1Length(data.length);
		return Bytes.concat(identifier(), length, data);
	}

	private static byte[] toAsn1Length(long length) {
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

	static ASN1Node parse(ByteBuffer data) {
		int offset = 0;

		// determine identifier:
		final byte[] identifier;
		if ((data.get(0) & 0b0001_1111) == 0b0001_1111) {
			// if last 5 bits of first byte are all 1, identifier consists of multiple bytes:
			// find first subsequent byte that does not have the MSB set
			do {
				offset++;
			} while ((data.get(offset) & 0b1000_0000) == 0b1000_0000);
			// identifier consists of all bytes up to and including the aforementioned byte:
			identifier = new byte[offset + 1];
			data.get(0, identifier, 0, identifier.length);
		} else {
			// otherwise identifier consists of a single byte
			identifier = new byte[] { data.get() };
			offset = 1;
		}
		assert offset == identifier.length;

		// determine length:
		final long length;
		byte firstLengthByte = data.get(offset++);
		if (firstLengthByte == (byte) 0b1000_0000) {
			// indefinite form as described in section 8.1.3.6 of ITU-T X.690
			throw new UnsupportedOperationException("Indefinite length encoding not supported");
		} else if ((firstLengthByte & 0b1000_0000) == 0) {
			// if MSB of first byte is 0, length is encoded in a single byte
			length = firstLengthByte;
		} else {
			// otherwise fist byte encodes the number of subsequent bytes...
			int n = firstLengthByte & 0b0111_1111;
			if (n > Long.BYTES) {
				throw new UnsupportedOperationException("Unsupported number of bytes for length encoding: " + n);
			}
			// ... and the subsequent bytes encode the actual length:
			long value = 0;
			for (int i = 0; i < n; i++) {
				byte b = data.get(offset++);
				value = (value << 8) | b & 0xFF;
			}
			if ((value & Long.MIN_VALUE) == Long.MIN_VALUE) { // oh now, overflow
				throw new UnsupportedOperationException("Encoded length larger than signed 64 bit int");
			}
			length = value;
		}

		// extract content:
		if ((identifier[0] & 0b0010_0000) == 0b0010_0000) {
			// constructed
			List<ASN1Node> children = new ArrayList<>();
			long endOfContent = offset + length;
			while (offset < endOfContent) {
				var slice = data.slice(offset, (int) (endOfContent - offset));
				var child = parse(slice);
				children.add(child);
				offset += child.size();
			}
			return new ASN1Constructed(identifier, ASN1Node.toAsn1Length(length), children);
		} else {
			// primitive
			var content = new byte[(int) length];
			data.get(offset, content, 0, content.length);
			return new ASN1Primitive(identifier, ASN1Node.toAsn1Length(length), content);
		}
	}

	static ASN1Node.ASN1Primitive primitive(byte[] identifier, byte[] data) {
		return new ASN1Primitive(identifier, ASN1Node.toAsn1Length(data.length), data);
	}

	static ASN1Node.ASN1Constructed constructed(byte[] identifier, ASN1Node... children) {
		var list = List.of(children);
		var len = list.stream().mapToInt(ASN1Node::size).sum();
		return new ASN1Constructed(identifier, ASN1Node.toAsn1Length(len), list);
	}

	record ASN1Primitive(byte[] identifier, byte[] length, byte[] data) implements ASN1Node {}

	record ASN1Constructed(byte[] identifier, byte[] length, List<ASN1Node> children) implements ASN1Node {

		public ASN1Node childAtIndex(int index) {
			return children.get(index);
		}

		public ASN1Node findChildWithId(byte[] id) {
			for (ASN1Node child : children) {
				if (Arrays.equals(child.identifier(), id)) {
					return child;
				}
			}
			return null;
		}

	}
}
