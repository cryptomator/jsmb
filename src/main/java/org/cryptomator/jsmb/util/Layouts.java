package org.cryptomator.jsmb.util;

import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

public interface Layouts {

	ValueLayout.OfByte BYTE = ValueLayout.JAVA_BYTE;
	ValueLayout.OfChar LE_UINT16 = ValueLayout.JAVA_CHAR_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
	ValueLayout.OfInt LE_INT32 = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
	ValueLayout.OfInt BE_INT32 = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);
	ValueLayout.OfLong LE_INT64= ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
	ValueLayout.OfLong BE_INT64= ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);

}
