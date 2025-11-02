package org.cryptomator.jsmb.srvs;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * [MS-SRVS] Global object
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/98c56700-5c9d-4246-b294-1357faa9ed57">[MS-SRVS] Global</a>
 */
public class SrvsGlobal {

	public static final SrvsGlobal INSTANCE = new SrvsGlobal();

	//TODO Removing entries
	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/cb311421-de4d-4cd7-bb05-ce52e03814e4">Inserting an entry</a>
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/d5a84302-764b-4d19-942c-4ec6eacc2703">Removing an entry</a>
	 */
	public final Map<Integer, SrvsSession> sessionList = Collections.synchronizedMap(new HashMap<>()); //Map<GlobalSessionId,SrvsSession> instead of List to make lookup easier

}
