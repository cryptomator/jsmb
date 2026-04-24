package org.cryptomator.jsmb;

/**
 * How this server identifies itself to NTLMv2 clients in the {@code CHALLENGE_MESSAGE} — the four
 * {@code MSV_AV_*} AV pairs Windows clients display in logon prompts and audit logs, plus the target realm name.
 *
 * <p>None of these values affect correctness (the authentication math runs off {@link Credentials} alone); they are
 * purely cosmetic / informational. Change them when you want the server to announce a specific hostname or domain.
 *
 * @param netbiosName   {@code MSV_AV_NB_COMPUTER_NAME} and {@code CHALLENGE_MESSAGE.TargetName}
 * @param netbiosDomain {@code MSV_AV_NB_DOMAIN_NAME}
 * @param dnsName       {@code MSV_AV_DNS_COMPUTER_NAME}
 * @param dnsDomain     {@code MSV_AV_DNS_DOMAIN_NAME} ({@code ""} when the server isn't joined to a DNS domain)
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e">MS-NLMP 2.2.2.1 AV_PAIR</a>
 */
public record ServerIdentity(String netbiosName, String netbiosDomain, String dnsName, String dnsDomain) {

	/** Matches jSMB's historical hardcoded values — swap in something host-specific for a real deployment. */
	public static final ServerIdentity DEFAULT = new ServerIdentity("jsmb", "jsmb", "jsmb", "");
}
