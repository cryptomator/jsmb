package org.cryptomator.jsmb.share;

/**
 * A single entry returned by {@link SmbOpen#listChildren(String)}. Carries enough metadata to
 * render any of the {@code FileXxxDirectoryInformation} classes required by {@code QUERY_DIRECTORY}.
 *
 * @param name     the child's name (UTF-16 at the wire level; a {@link String} here)
 * @param basic    timestamps + NT attribute bits
 * @param standard sizes + link / deletion / directory status
 */
public record DirEntry(String name, FileBasicInfo basic, FileStandardInfo standard) {}
