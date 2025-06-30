package org.cryptomator.jsmb.srvs;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/7d34d8e3-9046-440d-be57-927337406466">[MS-SRVS] Per Session</a>
 */
public record SrvsSession(int globalSessionId) {

	public static final AtomicInteger SRVS_SESSION_ID_GENERATOR = new AtomicInteger(Integer.MIN_VALUE);

}