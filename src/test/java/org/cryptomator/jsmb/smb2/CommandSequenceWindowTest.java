package org.cryptomator.jsmb.smb2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CommandSequenceWindowTest {

	private final CommandSequenceWindow window = new CommandSequenceWindow();

	@Test
	@DisplayName("A new window consists of MessageId 0 only")
	void initialWindow() {
		Assertions.assertEquals(1, window.available());
		Assertions.assertFalse(window.consume(1L, 1));
		Assertions.assertTrue(window.consume(0L, 1));
		Assertions.assertEquals(0, window.available());
	}

	@Test
	@DisplayName("A MessageId can't be used twice")
	void reuse() {
		window.consume(0L, 1);
		window.grant(2);

		Assertions.assertFalse(window.consume(0L, 1));
		Assertions.assertTrue(window.consume(1L, 1));
		Assertions.assertFalse(window.consume(1L, 1));
	}

	@Test
	@DisplayName("Granting credits extends the window by as many MessageIds")
	void grant() {
		window.consume(0L, 1);

		int granted = window.grant(3);

		Assertions.assertEquals(3, granted);
		Assertions.assertEquals(3, window.available());
		Assertions.assertFalse(window.consume(4L, 1));
		Assertions.assertTrue(window.consume(3L, 1));
	}

	@Test
	@DisplayName("MessageIds may be used out of order")
	void outOfOrder() {
		window.consume(0L, 1);
		window.grant(3);

		Assertions.assertTrue(window.consume(2L, 1));
		Assertions.assertTrue(window.consume(1L, 1));
		Assertions.assertTrue(window.consume(3L, 1));
		Assertions.assertEquals(0, window.available());
	}

	@Test
	@DisplayName("A multi-credit request takes consecutive MessageIds")
	void multiCredit() {
		window.consume(0L, 1);
		window.grant(4);

		Assertions.assertTrue(window.consume(1L, 3));
		Assertions.assertFalse(window.consume(3L, 1));
		Assertions.assertEquals(1, window.available());
		Assertions.assertTrue(window.consume(4L, 1));
	}

	@Test
	@DisplayName("A multi-credit request reaching beyond the window or into a used MessageId is refused and takes nothing")
	void multiCreditRefused() {
		window.consume(0L, 1);
		window.grant(3);
		window.consume(2L, 1);

		Assertions.assertFalse(window.consume(3L, 2)); // 4 is beyond the window
		Assertions.assertFalse(window.consume(1L, 2)); // 2 got used
		Assertions.assertEquals(2, window.available());
		Assertions.assertTrue(window.consume(1L, 1));
		Assertions.assertTrue(window.consume(3L, 1));
	}

	@Test
	@DisplayName("A MessageId beyond Long.MAX_VALUE is refused")
	void negativeMessageId() {
		Assertions.assertFalse(window.consume(-1L, 1));
	}

	@Test
	@DisplayName("A client never holds more than MAX_CREDITS credits")
	void maxCredits() {
		window.consume(0L, 1);

		int granted = window.grant(0xFFFF);

		Assertions.assertEquals(CommandSequenceWindow.MAX_CREDITS, granted);
		Assertions.assertEquals(0, window.grant(1));
		Assertions.assertEquals(CommandSequenceWindow.MAX_CREDITS, window.available());
	}

	@Test
	@DisplayName("A client that keeps skipping the lowest MessageId stops getting credits until it uses that one")
	void skippedMessageId() {
		window.consume(0L, 1);
		window.grant(2); // {1, 2}
		// uses every MessageId but 1 and asks for one credit in return each time
		long messageId = 2;
		int granted;
		do {
			Assertions.assertTrue(window.consume(messageId++, 1));
			granted = window.grant(1);
		} while (granted == 1 && messageId < 1_000_000);

		Assertions.assertEquals(0, granted);
		Assertions.assertEquals(1, window.available());
		Assertions.assertTrue(window.consume(1L, 1));
		Assertions.assertEquals(1, window.grant(1));
	}
}
