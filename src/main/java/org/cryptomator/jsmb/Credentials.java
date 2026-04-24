package org.cryptomator.jsmb;

/**
 * The single set of credentials this server accepts for NTLMv2 session setup. Passed to
 * {@link Server#start} and held for the server's lifetime. NTLMv2 needs the plaintext password on the server side
 * because validation happens by recomputing the response hash.
 *
 * <p>One credential pair per process is intentional — jSMB is embedded in applications that mount a single identity,
 * not multi-tenant file servers. If multi-user auth is ever needed, this type is the extension point.
 *
 * @param domain   NT domain or workgroup name the client must present (may be empty for workgroup-style logons)
 * @param user     account name the client must present
 * @param password plaintext password used to recompute the NTLMv2 response hash
 */
public record Credentials(String domain, String user, String password) {
}
