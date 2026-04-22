package org.cryptomator.jsmb.smb2;

import java.lang.foreign.MemorySegment;

/**
 * Catch-all wrapper for any SMB2 command the parser recognises by opcode but has no dedicated
 * request type for yet. Keeps the connection alive — the dispatcher responds with
 * {@code STATUS_NOT_SUPPORTED} instead of throwing, which matters inside compound chains and
 * for clients that probe for optional commands.
 */
public record UnhandledRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {}
