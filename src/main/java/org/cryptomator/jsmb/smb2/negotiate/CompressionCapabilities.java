package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * The context specifying the supported compression algorithms.
 *
 * @param data Data field of the SMB2_NEGOTIATE_CONTEXT
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271">SMB2_COMPRESSION_CAPABILITIES</a>
 */
public record CompressionCapabilities(MemorySegment data) implements NegotiateContext {

	public static final int FLAG_NONE = 0x00000000;
	public static final int FLAG_CHAINED = 0x00000001;

	public static final short ALG_NONE = 0x0000;
	public static final short ALG_LZNT1 = 0x0001;
	public static final short ALG_LZ77 = 0x0002;
	public static final short ALG_LZ77_HUFFMAN = 0x0003;
	public static final short ALG_PATTERN_V1 = 0x0004;
	public static final short ALG_LZ4 = 0x0005;

	public static NegotiateContext build(short[] compressionIds, int flags) {
		var compressionAlgorithms = MemorySegment.ofArray(compressionIds);
		var data = MemorySegment.ofArray(new byte[8 + (int) compressionAlgorithms.byteSize()]);
		data.set(Layouts.LE_INT16, 0, (short) compressionIds.length); // compression algorithm count
		data.set(Layouts.LE_INT32, 4, flags); // flags
		data.asSlice(8, compressionAlgorithms.byteSize()).copyFrom(compressionAlgorithms);
		return new CompressionCapabilities(data);
	}

	@Override
	public short contextType() {
		return NegotiateContext.COMPRESSION_CAPABILITIES;
	}

	public short compressionAlgorithmCount() {
		return data.get(Layouts.LE_INT16, 0);
	}

	public int flags() {
		return data.get(Layouts.LE_INT32, 4);
	}

	public short[] compressionAlgorithms() {
		return data.asSlice(8, compressionAlgorithmCount() * Short.BYTES).toArray(Layouts.LE_INT16);
	}
}
